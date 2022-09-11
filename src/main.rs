use byteorder::ByteOrder;
use byteorder::NetworkEndian;
use random::Source;
use sensor_common::props::PropertyReportV1;
use sensor_common::*;
use std::fmt::Display;
use std::io::Error as IoError;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::process::exit;
use std::time::Duration;

mod cli;

#[derive(Debug, thiserror::Error)]
enum CommandError {
    #[error("Sensor error: {0}")]
    SensorError(#[from] sensor_common::Error),
    #[error("IO-Error: {0}")]
    IoError(#[from] IoError),
    #[error("The device is not reachable")]
    DeviceUnreachable,
    #[error("The device does not implement the request")]
    NotImplemented,
    #[error("The request cannot be processed at this moment. {:?}", maybe_format_binary(.0))]
    NotAvailable(Option<Vec<u8>>),
}

fn maybe_format_binary(debug_info: &Option<Vec<u8>>) -> String {
    match debug_info {
        None => String::new(),
        Some(vec) => {
            let mut msg = String::from("  Further debug information were provided:\n");
            append_formatted_binary_table(&mut msg, &vec[..]).expect("Failed to extend string");
            msg
        }
    }
}

impl CommandError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CommandError::SensorError(_) => 2,
            CommandError::IoError(_) => 3,
            CommandError::DeviceUnreachable => -1,
            CommandError::NotImplemented => -2,
            CommandError::NotAvailable(_) => -3,
        }
    }
}

fn main() {
    let args: cli::Args = <cli::Args as clap::Parser>::parse();
    let context = Context {
        ip: args.ip,
        port: args.port,
        no_address: args.no_address,
        max_retries: args.max_retries,
    };

    exit(match context.handle(args.command) {
        Ok(_) => exitcode::OK,
        Err(e) => e.exit_code(),
    });
}

pub struct Context {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub no_address: bool,
    pub max_retries: usize,
}

impl Context {
    fn handle(&self, request_gen: impl RequestGenerator) -> Result<(), CommandError> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(1000)))?;

        let mut random = random::default();
        let mut buffer = [0; 2048];

        let address = SocketAddr::from((self.ip, self.port));

        for _ in 0..self.max_retries {
            let request = request_gen.new_request(random.read::<u8>());
            let id = request.id();
            let request_size = {
                let write = &mut &mut buffer[..];
                request.write(write)? + request_gen.append_payload(write)?
            };

            socket.send_to(&buffer[..request_size], address)?;
            if let Ok((size, address)) = socket.recv_from(&mut buffer[..]) {
                let read = &mut &buffer[..size];
                let response = Response::read(read)?;

                if address.ip() != self.ip {
                    eprintln!("Received UDP message from unexpected address: {}", address);
                    continue;
                }

                if response.id() != request.id() {
                    eprintln!(
                        "Received wrong response request-id: {}, response-id: {}",
                        request.id(),
                        response.id(),
                    );
                    continue;
                }

                match response {
                    Response::NotImplemented(_id) => {
                        return Err(CommandError::NotImplemented);
                    }
                    Response::NotAvailable(_) => {
                        let mut debug_info = None;
                        if read.available() > 0 {
                            let mut vec = Vec::new();
                            while read.available() > 0 {
                                vec.push(read.read_u8()?)
                            }
                            debug_info = Some(vec);
                        }
                        return Err(CommandError::NotAvailable(debug_info));
                    }
                    Response::Ok(_response_id, format) => {
                        let read_available = read.available();
                        let data = &buffer[(size - read_available)..];

                        match format {
                            Format::Empty => {}
                            Format::ValueOnly(Type::Bytes(18))
                                if request == Request::RetrieveNetworkConfiguration(id) =>
                            {
                                println!(
                                    "MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                    data[0], data[1], data[2], data[3], data[4], data[5]
                                );
                                println!();
                                println!(
                                    "IP:      {:}.{:}.{:}.{:}",
                                    data[6], data[7], data[8], data[9]
                                );
                                println!(
                                    "Subnet:  {:}.{:}.{:}.{:}",
                                    data[10], data[11], data[12], data[13]
                                );
                                println!(
                                    "Gateway: {:}.{:}.{:}.{:}",
                                    data[14], data[15], data[16], data[17]
                                );
                            }
                            Format::ValueOnly(Type::Bytes(n))
                                if request == Request::RetrieveDeviceInformation(id) =>
                            {
                                if n == 48 {
                                    // error on board on serialisation process causing overlap
                                    let frequency = NetworkEndian::read_u32(&data[0..]);
                                    let uptime = NetworkEndian::read_u32(&data[4..]);

                                    println!("Frequency: {} MHz", frequency / 1_000_000);
                                    println!("Uptime: {} ticks / {}s", uptime, uptime / frequency);
                                    println!("CPUID");
                                    println!(" - Implementer: 0x{:02x}", data[5]);
                                    println!(" - Variant:     0x{:02x}", data[6]);
                                    println!(" - PartNumber:  0x{:02x} 0x{:02x}", data[7], data[8]);
                                    println!(" - Revision:    0x{:02x}", data[9]);
                                } else {
                                    if n > 13 {
                                        let frequency = NetworkEndian::read_u32(&data[0..]) as u64;
                                        let uptime = NetworkEndian::read_u64(&data[4..]);

                                        let secs = (uptime / frequency) % 60;
                                        let mins = (uptime / frequency / 60) % 60;
                                        let hour = (uptime / frequency / 60 / 60) % 24;
                                        let days = uptime / frequency / 60 / 60 / 24;

                                        println!("Frequency: {} MHz", frequency / 1_000_000);
                                        println!(
                                            "Uptime: {} ticks / {} s",
                                            uptime,
                                            uptime / frequency
                                        );
                                        println!(
                                            "        {} days, {:02}:{:02}:{:02}",
                                            days, hour, mins, secs
                                        );
                                        println!("CPUID");
                                        println!(" - Implementer: 0x{:02x}", data[12]);
                                        println!(" - Variant:     0x{:02x}", data[13]);
                                        println!(
                                            " - PartNumber:  0x{:02x} 0x{:02x}",
                                            data[14], data[15]
                                        );
                                        println!(" - Revision:    0x{:02x}", data[16]);
                                        println!(
                                            "MAGIC_EEPROM_CRC_START: 0x{:02x} ({})",
                                            data[17], data[17]
                                        );
                                    }

                                    // the 19th byte is 0x00 to distinguish it from NetworkConfig
                                    if n > 19 {
                                        let module_name_len = data[19];
                                        println!(
                                            "FeaturedModule: {}",
                                            String::from_utf8_lossy(
                                                &data[20..20 + usize::from(module_name_len)]
                                            )
                                        );

                                        if n > 20 + module_name_len {
                                            let mut binary = String::new();
                                            append_formatted_binary_table(
                                                &mut binary,
                                                &data
                                                    [20 + usize::from(module_name_len)..n as usize],
                                            )
                                            .expect("Failed to extend string");
                                            println!("  Further information were provided:");
                                            println!("{}", binary);
                                        }
                                    }
                                }
                            }
                            Format::ValueOnly(Type::Bytes(n)) => {
                                let mut binary = String::new();
                                append_formatted_binary_table(&mut binary, &data[..n as usize])
                                    .expect("Failed to extend string");
                                println!("{}", binary);
                            }
                            Format::ValueOnly(format_type) => {
                                while read.available() > 0 {
                                    println!(
                                        "{}",
                                        format_generic_format_type(format_type, read, false)?
                                    );
                                }
                            }
                            Format::AddressOnly(format_type) => {
                                while read.available() > 0 {
                                    println!(
                                        "{}",
                                        format_generic_format_type(format_type, read, true)?
                                    );
                                }
                            }
                            Format::AddressValuePairs(address_type, value_type) => {
                                while read.available() > 0 {
                                    let formatted_address =
                                        format_generic_format_type(address_type, read, true)?;
                                    let formatted_value =
                                        format_generic_format_type(value_type, read, false)?;

                                    if self.no_address {
                                        println!("{}", formatted_value);
                                    } else {
                                        println!("{} {}", formatted_address, formatted_value);
                                    }
                                }
                            }
                        }
                        return Ok(());
                    }
                }
            }
        }
        Err(CommandError::DeviceUnreachable)
    }
}

impl RequestGenerator for cli::Command {
    fn new_request(&self, id: u8) -> Request {
        match self {
            Self::GetVersion(_) => Request::RetrieveVersionInformation(id),
            Self::GetInfo(_) => Request::RetrieveVersionInformation(id),
            Self::GetNetInfo(_) => Request::RetrieveNetworkConfiguration(id),
            Self::GetErrDump(_) => Request::RetrieveErrorDump(id),
            Self::I2cWriteRead(_) => Request::ReadSpecified(id, Bus::I2C),
            Self::OnewireRead(_) => Request::ReadSpecified(id, Bus::OneWire),
            Self::OnewireDiscover => Request::DiscoverAllOnBus(id, Bus::OneWire),
            Self::CustomRead(c) => Request::ReadSpecified(id, Bus::Custom(c.bus_address)),
            Self::SetNetworkIpSubnetGateway(c) => Request::SetNetworkIpSubnetGateway(
                id,
                c.ip.octets(),
                c.subnet.octets(),
                c.gateway.octets(),
            ),
            Self::SetNetworkMac(c) => Request::SetNetworkMac(id, c.mac.octets()),
            Self::ListProperties(c) if c.no_report => Request::ListComponents(id),
            Self::ListProperties(_) => Request::ListComponentsWithReportV1(id),
            Self::GetProperty(c) => Request::RetrieveProperty(
                id,
                c.property_id.bytes().len().min(u8::MAX as usize) as u8,
            ),
        }
    }

    fn append_payload(&self, writer: &mut impl Write) -> Result<usize, Error> {
        Ok(match self {
            Self::GetVersion(_) => 0,
            Self::GetInfo(_) => 0,
            Self::GetNetInfo(_) => 0,
            Self::GetErrDump(_) => 0,
            Self::I2cWriteRead(c) => {
                let read_len = c.i2c_read_len;
                let write_len = c.i2c_write_bytes.len().min(u8::MAX as usize) as u8;
                let bytes = &c.i2c_write_bytes[..usize::from(write_len)];
                writer.write_u8(read_len)? + writer.write_all(bytes)?
            }
            Self::OnewireRead(c) => c
                .sensor_address
                .iter()
                .map(|d| writer.write_all(&d.address))
                .sum::<Result<usize, _>>()?,
            Self::OnewireDiscover => 0,
            Self::CustomRead(_) => 0,
            Self::SetNetworkIpSubnetGateway(_) => 0,
            Self::SetNetworkMac(_) => 0,
            Self::ListProperties(_) => 0,
            Self::GetProperty(c) => {
                let pid = c.property_id.bytes();
                let len = pid.len().min(u8::MAX as usize) as u8;
                writer.write_all(&pid[..len as usize])?
            }
        })
    }
}

#[allow(clippy::needless_range_loop)]
fn append_formatted_binary_table(
    target: &mut String,
    binary: &[u8],
) -> Result<(), core::fmt::Error> {
    use core::fmt::Write;
    target.push_str(" ------+--------------------------+----------------------------------+------------------- \n");
    for i in 0..(binary.len() / 8) + 1 {
        write!(target, "  {:3}  : ", (i + 1))?;
        let from = i * 8;
        let to = (i + 1) * 8;
        for n in from..to.min(binary.len()) {
            write!(target, "{:02x} ", binary[n])?;
        }
        for _ in to.min(binary.len())..to {
            target.push_str("   ");
        }
        target.push_str("   ");
        for n in from..to.min(binary.len()) {
            write!(target, "{:>3} ", binary[n])?;
        }
        for _ in to.min(binary.len())..to {
            target.push_str("    ");
        }
        target.push_str("   ");
        for n in from..to.min(binary.len()) {
            if (binary[n] as char).is_alphanumeric() {
                write!(target, "{} ", binary[n] as char)?;
            } else {
                target.push_str(". ");
            }
        }
        target.push('\n');
    }
    Ok(())
}

fn format_generic_format_type(
    format_type: Type,
    read: &mut impl Read,
    is_address: bool,
) -> Result<String, CommandError> {
    macro_rules! read_impl_for {
        ($ty:ty) => {{
            let mut bytes = <$ty>::to_be_bytes(0);
            read.read_all(&mut bytes)?;
            let value = <$ty>::from_be_bytes(bytes);
            format!("{}", value)
        }};
    }

    Ok(match format_type {
        Type::F32 => format!(
            "{}",
            NetworkEndian::read_f32(&[
                read.read_u8()?,
                read.read_u8()?,
                read.read_u8()?,
                read.read_u8()?,
            ])
        ),
        Type::Bytes(len) => {
            let mut string = String::new();
            for i in 0..len {
                if i > 0 && is_address {
                    string.push(':');
                }
                use core::fmt::Write;
                write!(&mut string, "{:02x}", read.read_u8()?).expect("Failed to extend string");
            }
            string
        }
        Type::String(len) => {
            let len = len as usize;
            let mut vec = Vec::with_capacity(len);
            for _ in 0..len {
                vec.push(read.read_u8()?);
            }
            String::from_utf8_lossy(&vec[..len]).into()
        }
        Type::PropertyId => {
            let len = usize::from(read.read_u8()?);
            let mut string = String::with_capacity((3 * len).saturating_sub(1));
            for i in 0..len {
                use std::fmt::Write;
                write!(string, "{:02x}", read.read_u8()?).unwrap();
                if i + 1 < len {
                    string.push(':');
                }
            }
            string
        }
        Type::DynString => {
            let len = read.read_u8()?;
            if len > 0 {
                format_generic_format_type(Type::String(len), read, is_address)?
            } else {
                String::new()
            }
        }
        Type::DynBytes => {
            let len = read.read_u8()?;
            if len > 0 {
                format_generic_format_type(Type::Bytes(len), read, is_address)?
            } else {
                String::new()
            }
        }
        Type::DynListPropertyReportV1 => {
            let mut result = String::new();
            let mut reports = Vec::new();
            while read.available() > 0 {
                match PropertyReportV1::read(read) {
                    Err(e) => {
                        eprintln!(
                            "Invalid PropertyReportV1 encountered at number={}: {:?}",
                            reports.len(),
                            e
                        );
                        break;
                    }
                    Ok(report) => {
                        reports.push([
                            report.id_formatted(),
                            report
                                .type_hint
                                .map(|h| format!("{:?}", h))
                                .unwrap_or_default(),
                            report.description.unwrap_or_default(),
                            format!("{:?}", report.complexity),
                            format!(
                                "{}{}",
                                if report.read { "R" } else { "_" },
                                if report.write { "W" } else { "_" },
                            ),
                        ]);
                    }
                }
            }

            let header = ["id", "type", "description", "complexity", "mode"];

            let column_widths = reports
                .iter()
                .map(|columns| {
                    [
                        columns[0].len(),
                        columns[1].len(),
                        columns[2].len(),
                        columns[3].len(),
                        columns[4].len(),
                    ]
                })
                .chain([[
                    header[0].len(),
                    header[1].len(),
                    header[2].len(),
                    header[3].len(),
                    header[4].len(),
                ]])
                .reduce(|a, b| {
                    [
                        a[0].max(b[0]),
                        a[1].max(b[1]),
                        a[2].max(b[2]),
                        a[3].max(b[3]),
                        a[4].max(b[4]),
                    ]
                });

            if let Some(widths) = column_widths {
                fn print_line<const N: usize>(
                    result: &mut String,
                    width: [usize; N],
                    data: [impl Display; N],
                ) {
                    use std::fmt::Write;
                    for (column, width) in width.iter().enumerate() {
                        write!(result, "   {:w$}", data[column], w = width).unwrap();
                    }
                    writeln!(result).unwrap();
                }

                print_line(&mut result, widths, header);
                print_line(
                    &mut result,
                    widths,
                    [
                        core::iter::repeat('-').take(widths[0]).collect::<String>(),
                        core::iter::repeat('-').take(widths[1]).collect::<String>(),
                        core::iter::repeat('-').take(widths[2]).collect::<String>(),
                        core::iter::repeat('-').take(widths[3]).collect::<String>(),
                        core::iter::repeat('-').take(widths[4]).collect::<String>(),
                    ],
                );

                for report in reports {
                    print_line(&mut result, widths, report);
                }
            }

            result
        }

        Type::U128 => read_impl_for!(u128),
        Type::I128 => read_impl_for!(i128),
        Type::U64 => read_impl_for!(u64),
        Type::I64 => read_impl_for!(i64),
        Type::U32 => read_impl_for!(u32),
        Type::I32 => read_impl_for!(i32),
        Type::U16 => read_impl_for!(u16),
        Type::I16 => read_impl_for!(i16),
        Type::U8 => read_impl_for!(u8),
        Type::I8 => read_impl_for!(i8),
    })
}

pub trait RequestGenerator {
    fn new_request(&self, id: u8) -> Request;

    fn append_payload(&self, writer: &mut impl Write) -> Result<usize, Error>;
}
