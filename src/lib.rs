use can_dbc::{
    ByteOrder, Message, MessageId, MultiplexIndicator, Signal, SignalExtendedValueType,
    ValueDescription, ValueType, DBC,
};
use codegen::{Enum, Function, Impl, Scope, Struct};
use heck::{CamelCase, ShoutySnakeCase, SnakeCase};
use log::warn;
use socketcan::{EFF_MASK, SFF_MASK};

use std::fmt::Write;

/// Character that is prefixed before type names that are
/// are not starting with an alphabetic char.
const PREFIX_CHAR: char = 'X';

/// Character that is used to replace invalid characters
/// in type names.
const REPLACEMENT_CHAR: char = 'X';

/// Suffix that is append to the raw signal function
const RAW_FN_SUFFIX: &str = "raw_value";

type Result<T> = std::result::Result<T, std::fmt::Error>;

#[derive(Debug)]
pub struct DbccOpt {
    /// Should tokio SocketCan BCM streams be generated.
    /// This requires the `tokio-socketcan-bcm` crate.
    pub with_tokio: bool,
}

pub trait TypeName: ToOwned {
    fn to_type_name(&self) -> Self::Owned;
}

impl TypeName for str {
    fn to_type_name(&self) -> String {
        let mut out = String::with_capacity(self.len() + 1);
        let mut chars = self.chars();
        if let Some(first) = chars.next() {
            if !first.is_alphabetic() && first != '_' {
                warn!("string: {} is prefixed with `{}`", self, PREFIX_CHAR);
                out.push(PREFIX_CHAR);
            }
            out.push(first);
        }

        for chr in chars {
            if chr.is_digit(10) || chr.is_alphabetic() || chr == '_' {
                out.push(chr);
            } else {
                warn!(
                    "`{}` character in string: {} is replaced by `{}`",
                    chr, self, REPLACEMENT_CHAR
                );
                out.push(REPLACEMENT_CHAR);
            }
        }

        out
    }
}

fn to_enum_name(message_id: MessageId, signal_name: &str) -> String {
    format!("{}{}", &signal_name.to_camel_case(), message_id.0)
}

pub fn signal_enum(dbc: &DBC, val_desc: &ValueDescription) -> Option<Enum> {
    if let ValueDescription::Signal {
        ref message_id,
        ref signal_name,
        ref value_descriptions,
    } = val_desc
    {
        let mut sig_enum = Enum::new(&to_enum_name(*message_id, signal_name));
        sig_enum.allow("dead_code");
        sig_enum.vis("pub");
        sig_enum.repr("u64");
        sig_enum.derive("Debug");
        sig_enum.derive("Clone");
        sig_enum.derive("Copy");
        sig_enum.derive("PartialEq");
        let uniq_descs = value_descriptions
            .iter()
            .map(|desc| desc.b().to_camel_case().to_type_name())
            .collect::<std::collections::BTreeSet<_>>();
        for desc in uniq_descs {
            sig_enum.new_variant(&desc);
        }

        if let Some(signal) = dbc.signal_by_name(*message_id, signal_name) {
            let decoded_type = signal_decoded_type(dbc, *message_id, signal);
            sig_enum.new_variant(&format!("XValue({})", decoded_type));
        } else {
            sig_enum.new_variant("XValue(u64)");
        }
        return Some(sig_enum);
    }
    None
}

pub fn signal_enum_impl_from(dbc: &DBC, val_desc: &ValueDescription) -> Option<Impl> {
    if let ValueDescription::Signal {
        ref message_id,
        ref signal_name,
        ref value_descriptions,
    } = val_desc
    {
        let signal = dbc
            .signal_by_name(*message_id, signal_name)
            .expect(&format!("Value description missing signal {:#?}", val_desc));
        let signal_type = signal_decoded_type(dbc, *message_id, signal);

        let enum_name = to_enum_name(*message_id, signal_name);
        let mut enum_impl = Impl::new(codegen::Type::new(&enum_name));
        enum_impl.impl_trait(format!("From<{}>", signal_type));

        let from_fn = enum_impl.new_fn("from");
        from_fn.allow("dead_code");
        from_fn.arg("val", codegen::Type::new(&signal_type));
        from_fn.ret(codegen::Type::new("Self"));

        let mut matching = String::new();
        writeln!(&mut matching, "match val as u64 {{").unwrap();
        for value_description in value_descriptions {
            writeln!(
                &mut matching,
                "    {} => {}::{},",
                value_description.a(),
                enum_name,
                value_description.b().to_camel_case().to_type_name()
            )
            .unwrap();
        }
        writeln!(&mut matching, "    _ => {}::XValue(val),", enum_name).unwrap();
        write!(&mut matching, "}}").unwrap();

        from_fn.line(matching);

        return Some(enum_impl);
    }
    None
}

pub fn signal_fn_raw(dbc: &DBC, signal: &Signal, message_id: MessageId) -> Result<Function> {
    let raw_fn_name = format!("{}_{}", signal.name().to_snake_case(), RAW_FN_SUFFIX);

    let mut signal_fn = codegen::Function::new(&raw_fn_name);
    signal_fn.allow("dead_code");
    signal_fn.vis("pub");
    signal_fn.arg_ref_self();

    let signal_decoded_type = signal_decoded_type(dbc, message_id, signal);
    let signal_decoded_type = wrap_multiplex_indicator_type(signal, signal_decoded_type);
    signal_fn.ret(codegen::Type::new(&signal_decoded_type));

    let default_signal_comment = format!("Read {} signal from can frame", signal.name());
    let signal_comment = dbc
        .signal_comment(message_id, signal.name())
        .unwrap_or(&default_signal_comment);

    let signal_unit = if signal.unit().is_empty() {
        String::default()
    } else {
        format!("\nUnit: {}", signal.unit())
    };

    signal_fn.doc(&format!("{}{}", signal_comment, signal_unit));

    // Multiplexed signals are only available when the multiplexer switch value matches
    // the multiplexed indicator value defined in the DBC.
    if let MultiplexIndicator::MultiplexedSignal(switch_value) = signal.multiplexer_indicator() {
        let multiplexor_switch = dbc.message_multiplexor_switch(message_id).expect(&format!(
            "Multiplexed signal missing multiplex signal switch in message: {:#?}",
            signal
        ));
        let multiplexor_switch_fn = format!(
            "self.{}_{}()",
            multiplexor_switch.name().to_snake_case(),
            RAW_FN_SUFFIX
        );
        signal_fn.line(format!(
            "if {} != {} {{",
            multiplexor_switch_fn, switch_value
        ));
        signal_fn.line("    return None;");
        signal_fn.line("}");
    }

    let read_byte_order = match signal.byte_order() {
        ByteOrder::LittleEndian => "let frame_payload: u64 = LE::read_u64(&self.frame_payload);",
        ByteOrder::BigEndian => "let  frame_payload: u64 = BE::read_u64(&self.frame_payload);",
    };
    signal_fn.line(read_byte_order);

    let bit_msk_const = 2_u64.saturating_pow(*signal.signal_size() as u32) - 1;
    let signal_shift = shift_amount(
        *signal.byte_order(),
        *signal.start_bit(),
        *signal.signal_size(),
    );

    let calc = calc_raw(dbc, message_id, signal, signal_shift, bit_msk_const)?;
    let wrapped_calc = wrap_multiplex_indicator_value(signal, calc);
    signal_fn.line(wrapped_calc);

    Ok(signal_fn)
}

pub fn signal_fn_enum(signal: &Signal, enum_type: String) -> Result<Function> {
    let mut signal_fn = codegen::Function::new(&signal.name().to_snake_case());
    signal_fn.allow("dead_code");
    signal_fn.vis("pub");
    signal_fn.arg_ref_self();

    signal_fn.ret(wrap_multiplex_indicator_type(signal, enum_type.clone()));

    let raw_fn_name = format!("{}_{}", signal.name().to_snake_case(), RAW_FN_SUFFIX);

    // Multiplexed signals are only available when the multiplexer switch value matches
    // the multiplexed indicator value defined in the DBC.
    let _ = match signal.multiplexer_indicator() {
        MultiplexIndicator::MultiplexedSignal(_) => {
            signal_fn.line(format!("self.{}().map({}::from)", raw_fn_name, enum_type))
        }
        _ => signal_fn.line(format!("{}::from(self.{}())", enum_type, raw_fn_name)),
    };

    Ok(signal_fn)
}

fn calc_raw(
    dbc: &DBC,
    message_id: MessageId,
    signal: &Signal,
    signal_shift: u64,
    bit_msk_const: u64,
) -> Result<String> {
    let signal_decoded_type = signal_decoded_type(dbc, message_id, signal);
    let boolean_signal =
        *signal.signal_size() == 1 && *signal.factor() == 1.0 && *signal.offset() == 0.0;

    let mut calc = String::new();

    // No shift required if start_bit == 0
    let shift = if signal_shift == 0 {
        "frame_payload".to_string()
    } else {
        format!("(frame_payload >> {})", signal_shift)
    };

    write!(&mut calc, "({} & {:#X})", shift, bit_msk_const)?;

    if !boolean_signal {
        write!(&mut calc, " as {}", signal_decoded_type)?;
    }

    if *signal.factor() != 1.0 {
        write!(&mut calc, " * {:.6}", signal.factor())?;
    }

    if *signal.offset() != 0.0 {
        write!(&mut calc, " + {}{}", signal.offset(), signal_decoded_type)?;
    }

    if boolean_signal {
        write!(&mut calc, " == 1")?;
    }

    Ok(calc)
}

/// This wraps multiplex indicators in  Option types.
/// Multiplexed signals are only available when the multiplexer switch value matches
/// the multiplexed indicator value defined in the DBC.
fn wrap_multiplex_indicator_type(signal: &Signal, signal_type: String) -> String {
    match signal.multiplexer_indicator() {
        MultiplexIndicator::MultiplexedSignal(_) => format!("Option<{}>", signal_type).to_string(),
        _ => signal_type,
    }
}

/// This wraps multiplex indicators in  Option types.
/// Multiplexed signals are only available when the multiplexer switch value matches
/// the multiplexed indicator value defined in the DBC.
fn wrap_multiplex_indicator_value(signal: &Signal, signal_value: String) -> String {
    match signal.multiplexer_indicator() {
        MultiplexIndicator::MultiplexedSignal(_) => format!("Some({})", signal_value).to_string(),
        _ => signal_value,
    }
}

fn signal_decoded_type(dbc: &DBC, message_id: MessageId, signal: &Signal) -> String {
    if let Some(extended_value_type) = dbc.extended_value_type_for_signal(message_id, signal.name())
    {
        match extended_value_type {
            SignalExtendedValueType::IEEEfloat32Bit => return "f32".to_string(),
            SignalExtendedValueType::IEEEdouble64bit => return "f64".to_string(),
            SignalExtendedValueType::SignedOrUnsignedInteger => (), // Handled below, also part of the Signal itself
        }
    }

    if !(*signal.offset() == 0.0 && *signal.factor() == 1.0) {
        return "f64".to_string();
    }

    let prefix_int_sign = match *signal.value_type() {
        ValueType::Signed => "i",
        ValueType::Unsigned => "u",
    };

    match signal.signal_size() {
        _ if *signal.signal_size() == 1 => "bool".to_string(),
        _ if *signal.signal_size() > 1 && *signal.signal_size() <= 8 => {
            format!("{}8", prefix_int_sign).to_string()
        }
        _ if *signal.signal_size() > 8 && *signal.signal_size() <= 16 => {
            format!("{}16", prefix_int_sign).to_string()
        }
        _ if *signal.signal_size() > 16 && *signal.signal_size() <= 32 => {
            format!("{}32", prefix_int_sign).to_string()
        }
        _ => format!("{}64", prefix_int_sign).to_string(),
    }
}

fn shift_amount(byte_order: ByteOrder, start_bit: u64, signal_size: u64) -> u64 {
    match byte_order {
        ByteOrder::LittleEndian => start_bit,
        ByteOrder::BigEndian => 64 - signal_size - ((start_bit / 8) * 8 + (7 - (start_bit % 8))),
    }
}

fn message_const(message: &Message) -> String {
    format!(
        "#[allow(dead_code)]\npub const MESSAGE_ID_{}: u32 = {};",
        message.message_name().to_shouty_snake_case(),
        message.message_id().0
    )
}

fn message_struct(dbc: &DBC, message: &Message) -> Struct {
    let mut message_struct = Struct::new(&message.message_name().to_camel_case());
    if let Some(message_comment) = dbc.message_comment(*message.message_id()) {
        message_struct.doc(message_comment);
    }
    message_struct.allow("dead_code");
    message_struct.derive("Debug");
    message_struct.vis("pub");
    message_struct.field("frame_payload", "Vec<u8>");
    message_struct
}

fn message_impl(opt: &DbccOpt, dbc: &DBC, message: &Message) -> Result<Impl> {
    let mut msg_impl = Impl::new(codegen::Type::new(&message.message_name().to_camel_case()));

    let new_fn = msg_impl.new_fn("new");
    new_fn.allow("dead_code");
    new_fn.vis("pub");
    new_fn.arg("mut frame_payload", codegen::Type::new("Vec<u8>"));
    new_fn.line("frame_payload.resize(8, 0);");
    new_fn.line(format!(
        "{} {{ frame_payload }}",
        message.message_name().to_camel_case()
    ));
    new_fn.ret(codegen::Type::new(&message.message_name().to_camel_case()));

    if opt.with_tokio {
        msg_impl.push_fn(message_stream(message));
    }

    // send function
    // This is a quick and dirty proof of concept
    let send_fn = msg_impl.new_fn("send");
    send_fn.allow("dead_code");
    send_fn.vis("pub");
    send_fn.arg("can_interface", codegen::Type::new("&str"));
    send_fn.line("let mut payload = 0u64;");

    for signal in message.signals() {
        let signal_decoded_type = signal_decoded_type(dbc, *message.message_id(), signal);
        let signal_decoded_type = wrap_multiplex_indicator_type(signal, signal_decoded_type);
        send_fn.arg(&signal.name().to_snake_case(), codegen::Type::new(&signal_decoded_type));
        
        let signal_shift = shift_amount(
            *signal.byte_order(),
            *signal.start_bit(),
            *signal.signal_size(),
        );
        let divider_string = if signal.factor != 1f64 { format!(" / {}", signal.factor) } else { String::from("") };

        send_fn.line(format!("payload |= (({}{}) as u64) << {};", &signal.name().to_snake_case(), divider_string, signal_shift));
    }
    send_fn.line("let mut frame_payload: [u8; 8] = [0;8];");
    // TODO figure out bit order of message
    // let write_byte_order = match signal.byte_order() {
    //     ByteOrder::LittleEndian => "LE::write_u64_into(&[payload], &mut frame_payload);",
    //     ByteOrder::BigEndian => "BE::write_u64_into(&[payload], &mut frame_payload);",
    // };
    send_fn.line("BE::write_u64_into(&[payload], &mut frame_payload);");
    send_fn.line("let socket_tx = CANSocket::open(&can_interface).unwrap();");
    send_fn.line(format!("let can_frame = CANFrame::new({}, &frame_payload, false, false).unwrap();", message.message_id().0));
    send_fn.line("let _write = socket_tx.write_frame(&can_frame);");
    // End send function

    for signal in message.signals() {
        msg_impl.push_fn(signal_fn_raw(dbc, signal, *message.message_id())?);

        // Check if this signal can be turned into an enum
        let enum_type = dbc
            .value_descriptions_for_signal(*message.message_id(), signal.name())
            .map(|_| to_enum_name(*message.message_id(), signal.name()));
        if let Some(enum_type) = enum_type {
            msg_impl.push_fn(signal_fn_enum(signal, enum_type)?);
        }
    }

    Ok(msg_impl)
}

/// Generate message stream using socketcan's Broadcast Manager filters via socketcan-tokio.
fn message_stream(message: &Message) -> Function {
    let mut stream_fn = codegen::Function::new("stream");
    stream_fn.allow("dead_code");
    stream_fn.vis("pub");

    stream_fn.arg("can_interface", codegen::Type::new("&str"));
    stream_fn.arg("ival1", codegen::Type::new("&std::time::Duration"));
    stream_fn.arg("ival2", codegen::Type::new("&std::time::Duration"));

    let ret = format!(
        "std::io::Result<impl Stream<Item = Result<{}, std::io::Error>>>",
        message.message_name().to_camel_case()
    );
    stream_fn.ret(ret);

    stream_fn.line("let socket = BCMSocket::open_nb(&can_interface)?;");

    let message_id = match message.message_id().0 & EFF_MASK {
        0..=SFF_MASK => format!(
            "let message_id = CANMessageId::SFF({} as u16);",
            (message.message_id().0 & SFF_MASK).to_string()
        ),
        SFF_MASK..=EFF_MASK => format!(
            "let message_id = CANMessageId::EFF({});",
            (message.message_id().0 & EFF_MASK).to_string()
        ),
        _ => unreachable!(),
    };
    stream_fn.line(message_id);

    stream_fn.line("let frame_stream = socket.filter_id_incoming_frames(message_id, ival1.clone(), ival2.clone())?.compat();");
    stream_fn.line(format!(
        "let f = frame_stream.map(|frame| frame.map(|frame| {}::new(frame.data().to_vec())));",
        message.message_name().to_camel_case()
    ));
    stream_fn.line("Ok(f)");

    stream_fn
}

/// Genérate code for reading CAN signals
///
/// Example:
/// ```
/// use blake2::{Blake2b, Digest};
/// use dbcc::{can_code_gen, DbccOpt};
/// use generic_array::GenericArray;
/// use typenum::U64;
///
/// use std::fs;
/// use std::io::{self, prelude::*};
/// use std::path::{Path, PathBuf};
///
/// fn dbc_file_hash(dbc_path: &Path) -> io::Result<GenericArray<u8, U64>> {
///     let mut file = fs::File::open(&dbc_path)?;
///     let mut hasher = Blake2b::new();
///     let _n = io::copy(&mut file, &mut hasher)?;
///     Ok(hasher.result())
/// }
///
/// fn main() -> io::Result<()> {
///    let file_path_buf = PathBuf::from("./examples/j1939.dbc");
///    let file_path = file_path_buf.as_path();
///    let file_name = file_path.file_name().and_then(|f| f.to_str()).unwrap_or_else(|| "N/A");
///    let file_hash = dbc_file_hash(file_path)?;
///    let file_hash = format!("Blake2b: {:X}", file_hash);
///    let mut f = fs::File::open("./examples/j1939.dbc").expect("Failed to open input file");
///    let mut buffer = Vec::new();
///    f.read_to_end(&mut buffer).expect("Failed to read file");
///    let dbc_content = can_dbc::DBC::from_slice(&buffer).expect("Failed to parse DBC file");
///    let opt = DbccOpt { with_tokio: true };
///    let code = can_code_gen(&opt, &dbc_content, file_name, &file_hash).expect("Failed to generate rust code");
///    println!("{}", code.to_string());
///    Ok(())
/// }
///```
pub fn can_code_gen(opt: &DbccOpt, dbc: &DBC, file_name: &str, file_hash: &str) -> Result<Scope> {
    let mut scope = Scope::new();

    scope.raw(&format!(
        "// Generated based on\n// File Name: {}\n// DBC Version: {}\n// {}",
        file_name,
        dbc.version().0,
        file_hash
    ));
    scope.import("byteorder", "{ByteOrder, BE, LE}");
    scope.import("socketcan", "{CANSocket, CANFrame}");
    if opt.with_tokio {
        scope.import("futures::stream", "Stream");
        scope.import("futures_util::compat", "Stream01CompatExt");
        scope.import("futures_util::stream", "StreamExt");
        scope.import("tokio_socketcan_bcm", "{CANMessageId, BCMSocket}");
    }

    for message in dbc.messages() {
        scope.raw(&message_const(message));
    }

    for value_description in dbc.value_descriptions() {
        if let Some(signal_enum) = signal_enum(dbc, value_description) {
            scope.push_enum(signal_enum);
        }

        if let Some(enum_impl) = signal_enum_impl_from(dbc, value_description) {
            scope.push_impl(enum_impl);
        }
    }

    for message in dbc.messages() {
        scope.push_struct(message_struct(&dbc, message));
        scope.push_impl(message_impl(opt, &dbc, message)?);
    }

    Ok(scope)
}
