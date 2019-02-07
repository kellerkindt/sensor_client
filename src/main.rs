extern crate byteorder;
extern crate clap;
extern crate random;

extern crate onewire;
extern crate sensor_common;

use byteorder::ByteOrder;
use byteorder::NetworkEndian;

use onewire::Device;
use sensor_common::*;

use std::io::Error as IoError;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::time::Duration;

use random::Source;

use std::u8;

enum CommandError {
    SensorError(Error),
    IoError(IoError),
    DeviceUnreachable,
    NotImplemented,
    NotAvailable(Option<Vec<u8>>),
}

impl From<Error> for CommandError {
    fn from(e: Error) -> Self {
        CommandError::SensorError(e)
    }
}

impl From<IoError> for CommandError {
    fn from(e: IoError) -> Self {
        CommandError::IoError(e)
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

    pub fn err_msg(&self) -> String {
        match self {
            CommandError::SensorError(e) => format!("Protocol error: {:?}", e),
            CommandError::IoError(e) => format!("Local IoError: {:?}", e),
            CommandError::DeviceUnreachable => "The device is not reachable".into(),
            CommandError::NotImplemented => "The device does not implement the request".into(),
            CommandError::NotAvailable(debug_info) => {
                let msg = "The request cannot be processed at this moment".into();
                match debug_info {
                    None => msg,
                    Some(vec) => {
                        use std::ops::Add;
                        let mut msg = msg.add("\n\n");
                        let mut msg = msg.add("  Further debug information were provided:\n");
                        print_binary(&mut msg, &vec[..]);
                        msg
                    }
                }
            }
        }
    }
}

fn main() {
    match handle_command(read_command(), 5) {
        Err(e) => {
            eprintln!("{}", e.err_msg());
            std::process::exit(e.exit_code());
        }
        Ok(_) => std::process::exit(0),
    }
}

fn print_binary(target: &mut String, binary: &[u8]) {
    target.push_str(" ------+--------------------------+----------------------------------+------------------- \n");
    for i in 0..(binary.len() / 8) + 1 {
        target.push_str(&format!("  {:3}  : ", (i + 1)));
        let from = i * 8;
        let to = (i + 1) * 8;
        for n in from..to.min(binary.len()) {
            target.push_str(&format!("{:02x} ", binary[n]));
        }
        for _ in to.min(binary.len())..to {
            target.push_str("   ");
        }
        target.push_str("   ");
        for n in from..to.min(binary.len()) {
            target.push_str(&format!("{:>3} ", binary[n]));
        }
        for _ in to.min(binary.len())..to {
            target.push_str("    ");
        }
        target.push_str("   ");
        for n in from..to.min(binary.len()) {
            if (binary[n] as char).is_alphanumeric() {
                target.push_str(&format!("{} ", binary[n] as char));
            } else {
                target.push_str(". ");
            }
        }
        target.push_str("\n");
    }
}

fn handle_command(command: Command, max_retries: usize) -> Result<(), CommandError> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(1000)))?;

    let mut random = random::default();
    let mut buffer = [0; 2048];

    let address = command.params().address.clone();

    for _ in 0..max_retries {
        let request = command.new_request(random.read::<u8>());
        let id = request.id();
        let request_size = {
            let write = &mut &mut buffer[..] as &mut Write;
            request.write(write)? + command.append_payload(write)?
        };

        socket.send_to(&buffer[..request_size], address)?;
        match socket.recv_from(&mut buffer[..]) {
            Ok((size, address)) => {
                let read = &mut &buffer[..size] as &mut Read;
                let response = Response::read(read)?;

                if address.ip().ne(&command.params().address.ip()) {
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
                        let data = &buffer[(size - read.available())..];

                        match format {
                            Format::Empty => {}
                            Format::ValueOnly(Type::Bytes(18)) if request == Request::RetrieveNetworkConfiguration(id)  => {
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
                            Format::ValueOnly(Type::Bytes(n)) if request == Request::RetrieveDeviceInformation(id)  => {
                                if n == 48 {
                                    // error on board on serialisation process causing overlap
                                    let frequency = NetworkEndian::read_u32(&data[0..]);
                                    let uptime = NetworkEndian::read_u32(&data[4..]);

                                    println!("Frequency: {} MHz", frequency / 1_000_000);
                                    println!("Uptime: {} ticks / {}s", uptime, uptime / frequency);
                                    println!("CPUID");
                                    println!(" - Implementer: {:02x}", data[5]);
                                    println!(" - Variant:     {:02x}", data[6]);
                                    println!(
                                        " - PartNumber:  {:04x}",
                                        NetworkEndian::read_u16(&data[7..])
                                    );
                                    println!(" - Revision:    {:02x}", data[9]);
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
                                        println!(" - Implementer: {:02x}", data[12]);
                                        println!(" - Variant:     {:02x}", data[13]);
                                        println!(
                                            " - PartNumber:  {:04x}",
                                            NetworkEndian::read_u16(&data[14..])
                                        );
                                        println!(" - Revision:    {:02x}", data[16]);
                                        println!(
                                            "MAGIC_EEPROM_CRC_START: 0x{:02x} ({})",
                                            data[17], data[17]
                                        );
                                    }
                                    // the 19th byte is 0x00 to distinguish it from NetworkConfig
                                    if n > 19 {
                                        let mut binary = String::new();
                                        print_binary(&mut binary, &data[14..n as usize]);
                                        println!("  Further information were provided:");
                                        println!("{}", binary);
                                    }
                                }
                            }
                            Format::ValueOnly(Type::Bytes(n)) => {
                                let mut binary = String::new();
                                print_binary(&mut binary, &data[..n as usize]);
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

                                    if command.params().no_address {
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
            Err(_) => {
                // retry
            }
        }
    }
    Err(CommandError::DeviceUnreachable)
}

fn format_generic_format_type(
    format_type: Type,
    read: &mut Read,
    is_address: bool,
) -> Result<String, CommandError> {
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
                    string.push_str(":");
                }
                string.push_str(&format!("{:02x}", read.read_u8()?));
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
    })
}

use clap::{App, AppSettings, Arg, SubCommand};
use std::net::SocketAddrV4;
use std::str::FromStr;

const ARG_IP_ADDR: &'static str = "ip";
const ARG_SUBNET: &'static str = "subnet";
const ARG_GATEWAY: &'static str = "gateway";
const ARG_MAC: &'static str = "mac";
const ARG_PORT: &'static str = "port";
const ARG_ONEWIRE_ADDR: &'static str = "onewire-addr";
const ARG_BUS_ADDR: &'static str = "bus-addr";
const ARG_I2C_READ_LEN: &'static str = "i2c-read-len";
const ARG_I2C_WRITE_BYTES: &'static str = "i2c-write-bytes";

const SUBCOMMAND_GET_VERSION: &'static str = "get-version";
const SUBCOMMAND_GET_NET_CONF: &'static str = "get-network-config";
const SUBCOMMAND_GET_INFO: &'static str = "get-info";
const SUBCOMMAND_READ_ONEWIRE: &'static str = "onewire-read";
const SUBCOMMAND_READ_CUSTOM_BUS: &'static str = "custom-read";
const SUBCOMMAND_DISC_ONEWIRE: &'static str = "onewire-discover";
const SUBCOMMAND_I2C_WRITE_READ: &'static str = "i2c-write-read";
const SUBCOMMAND_SET_IP_SUB_GW: &'static str = "set-network-ip-subnet-gateway";
const SUBCOMMAND_SET_MAC: &'static str = "set-network-mac";

const PARAMETER_NO_ADDRESS: &str = "no-address";

#[derive(Clone, Debug)]
enum Command {
    GetVersion(Parameter),
    GetNetConf(Parameter),
    GetDevInfo(Parameter),
    ReadOneWire(Parameter, Vec<Device>),
    ReadBus(Parameter, u8),
    DiscOneWire(Parameter),
    I2cWriteRead(Parameter, Vec<u8>, u8),
    SetNetIpSubGate(Parameter, Ipv4Addr, Ipv4Addr, Ipv4Addr),
    SetNetMac(Parameter, [u8; 6]),
}

impl Command {
    pub fn params(&self) -> &Parameter {
        match self {
            Command::GetVersion(params) => &params,
            Command::GetNetConf(params) => &params,
            Command::GetDevInfo(params) => &params,
            Command::ReadOneWire(params, _) => &params,
            Command::ReadBus(params, _) => &params,
            Command::DiscOneWire(params) => &params,
            Command::I2cWriteRead(params, _, _) => &params,
            Command::SetNetIpSubGate(params, _, _, _) => &params,
            Command::SetNetMac(params, _) => &params,
        }
    }
}

pub trait RequestGenerator {
    fn new_request(&self, id: u8) -> Request;

    fn append_payload(&self, writer: &mut Write) -> Result<usize, Error>;
}

impl RequestGenerator for Command {
    fn new_request(&self, id: u8) -> Request {
        match self {
            Command::GetVersion(_) => Request::RetrieveVersionInformation(id),
            Command::GetNetConf(_) => Request::RetrieveNetworkConfiguration(id),
            Command::GetDevInfo(_) => Request::RetrieveDeviceInformation(id),
            Command::ReadOneWire(_, _) => Request::ReadSpecified(id, Bus::OneWire),
            Command::ReadBus(_, bus) => Request::ReadSpecified(id, Bus::Custom(*bus)),
            Command::DiscOneWire(_) => Request::DiscoverAllOnBus(id, Bus::OneWire),
            Command::I2cWriteRead(..) => Request::ReadSpecified(id, Bus::I2C),
            Command::SetNetIpSubGate(_, ip, sub, gate) => {
                Request::SetNetworkIpSubnetGateway(id, ip.octets(), sub.octets(), gate.octets())
            }
            Command::SetNetMac(_, mac) => Request::SetNetworkMac(id, mac.clone()),
        }
    }

    fn append_payload(&self, writer: &mut Write) -> Result<usize, Error> {
        Ok(match self {
            Command::GetVersion(_) => 0,
            Command::GetNetConf(_) => 0,
            Command::GetDevInfo(_) => 0,
            Command::ReadOneWire(_, devices) => {
                let mut count = 0;
                for device in devices.iter() {
                    count += writer.write_all(&device.address)?;
                }
                count
            }
            Command::ReadBus(_, _) => 0,
            Command::DiscOneWire(_) => 0,
            Command::I2cWriteRead(_, write, read_len) => {
                writer.write_u8(*read_len)? + writer.write_all(&write[..])?
            }
            Command::SetNetIpSubGate(_, _, _, _) => 0,
            Command::SetNetMac(_, _) => 0,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Parameter {
    address: SocketAddr,
    no_address: bool,
}

fn read_command() -> Command {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::NeedsSubcommandHelp)
        .setting(AppSettings::ColoredHelp)
        .arg(
            Arg::with_name(ARG_IP_ADDR)
                .short("i")
                .long("ip")
                .value_name("IP_ADDRESS")
                .multiple(false)
                .required(true)
                .index(1)
                .help("Ip address of the device")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ARG_PORT)
                .short("p")
                .long("port")
                .value_name("PORT_NUMBER")
                .multiple(false)
                .required(false)
                .index(2)
                .help("The port for the device")
                .takes_value(true)
                .default_value("51"),
        )
        .arg(
            Arg::with_name(PARAMETER_NO_ADDRESS)
                .long(PARAMETER_NO_ADDRESS)
                .required(false)
                .multiple(false)
                .takes_value(false)
                .help("Prints no address of received values"),
        )
        .subcommand(
            SubCommand::with_name(SUBCOMMAND_GET_VERSION)
                .about("Reads the version from the specified device"),
        )
        .subcommand(
            SubCommand::with_name(SUBCOMMAND_GET_INFO)
                .about("Reads general information from the device"),
        )
        .subcommand(
            SubCommand::with_name(SUBCOMMAND_GET_NET_CONF)
                .alias("get-net-conf")
                .alias("get-network-conf")
                .alias("get-net-config")
                .about("Reads the network configuration from the specified device"),
        )
        .subcommand(
            SubCommand::with_name(SUBCOMMAND_I2C_WRITE_READ)
                .about("Lets the specified device write bytes to the i2c channel and then transmit the result back")
                .arg(
                    Arg::with_name(ARG_I2C_READ_LEN)
                        .required(true)
                        .multiple(false)
                        .value_name("I2C_READ_LEN")
                        .help("Amount of bytes to read from the i2c device"),
                )
                .arg(
                    Arg::with_name(ARG_I2C_WRITE_BYTES)
                        .required(true)
                        .multiple(true)
                        .value_name("I2C_WRITE_BYTES")
                        .help("Bytes (hex coded, without leading 0x) to write on the i2c bus"),
                ),
        )
        .subcommand(
            SubCommand::with_name(SUBCOMMAND_I2C_WRITE_READ)
                .about("Lets the specified device read values from the specified OneWire sensors")
                .arg(
                    Arg::with_name(ARG_ONEWIRE_ADDR)
                        .required(true)
                        .multiple(true)
                        .value_name("SENSOR_ADDRESS")
                        .help("OneWire address"),
                ),
        )
        .subcommand(
            SubCommand::with_name(SUBCOMMAND_READ_CUSTOM_BUS)
                .about("Lets the specified device read values from the specified bus")
                .arg(
                    Arg::with_name(ARG_BUS_ADDR)
                        .required(true)
                        .multiple(false)
                        .value_name("BUS_ADDRESS")
                        .help("Bus address"),
                ),
        )
        .subcommand(
            SubCommand::with_name(SUBCOMMAND_DISC_ONEWIRE)
                .about("Lets the specified device discover all connected OneWire sensors"),
        )
        .subcommand(
            SubCommand::with_name(SUBCOMMAND_SET_IP_SUB_GW)
                .about("Reconfigures the devices' ip, subnet and gateway addresses")
                .arg(
                    Arg::with_name(ARG_IP_ADDR)
                        .required(true)
                        .index(1)
                        .takes_value(true)
                        .value_name("IP")
                        .help("The new ip address for the device"),
                )
                .arg(
                    Arg::with_name(ARG_SUBNET)
                        .required(true)
                        .index(2)
                        .takes_value(true)
                        .value_name("SUBNET")
                        .help("The new subnet address of the device"),
                )
                .arg(
                    Arg::with_name(ARG_GATEWAY)
                        .required(true)
                        .index(3)
                        .takes_value(true)
                        .value_name("GATEWAY")
                        .help("The new gateway address of the device"),
                ),
        )
        .subcommand(
            SubCommand::with_name(SUBCOMMAND_SET_MAC)
                .about("Reconfigures the devices' mac address")
                .arg(
                    Arg::with_name(ARG_MAC)
                        .required(true)
                        .index(1)
                        .takes_value(true)
                        .value_name("MAC")
                        .help("The new mac address for the device"),
                ),
        )
        .get_matches();

    let ip = Ipv4Addr::from_str(matches.value_of(ARG_IP_ADDR).unwrap()).unwrap();
    let port = matches.value_of(ARG_PORT).unwrap().parse::<u16>().unwrap();
    let params = Parameter {
        address: SocketAddr::V4(SocketAddrV4::new(ip, port)),
        no_address: matches.is_present(PARAMETER_NO_ADDRESS),
    };

    match matches.subcommand() {
        (SUBCOMMAND_GET_VERSION, _) => Command::GetVersion(params),
        (SUBCOMMAND_GET_NET_CONF, _) => Command::GetNetConf(params),
        (SUBCOMMAND_GET_INFO, _) => Command::GetDevInfo(params),
        (SUBCOMMAND_READ_ONEWIRE, m) => Command::ReadOneWire(
            params,
            m.unwrap()
                .values_of_lossy(ARG_ONEWIRE_ADDR)
                .map(|addresses_str| {
                    let mut devices = Vec::new();
                    for address_str in addresses_str {
                        devices.push(Device {
                            address: [
                                u8::from_str_radix(&address_str[0..2], 16).unwrap(),
                                u8::from_str_radix(&address_str[3..5], 16).unwrap(),
                                u8::from_str_radix(&address_str[6..8], 16).unwrap(),
                                u8::from_str_radix(&address_str[9..11], 16).unwrap(),
                                u8::from_str_radix(&address_str[12..14], 16).unwrap(),
                                u8::from_str_radix(&address_str[15..17], 16).unwrap(),
                                u8::from_str_radix(&address_str[18..20], 16).unwrap(),
                                u8::from_str_radix(&address_str[21..23], 16).unwrap(),
                            ],
                        })
                    }
                    devices
                })
                .unwrap(),
        ),
        (SUBCOMMAND_I2C_WRITE_READ, m) => Command::I2cWriteRead(
            params,
            m.unwrap()
                .values_of_lossy(ARG_I2C_WRITE_BYTES)
                .map(|bytes_char| {
                    bytes_char
                        .into_iter()
                        .map(|byte_char| u8::from_str_radix(&byte_char, 16).unwrap())
                        .collect::<Vec<_>>()
                })
                .unwrap(),
            m.unwrap()
                .value_of_lossy(ARG_I2C_READ_LEN)
                .map(|len| len.parse::<u8>().unwrap())
                .unwrap(),
        ),
        (SUBCOMMAND_READ_CUSTOM_BUS, m) => Command::ReadBus(
            params,
            (&m.unwrap().value_of(ARG_BUS_ADDR).unwrap() as &str)
                .parse::<u8>()
                .unwrap(),
        ),
        (SUBCOMMAND_DISC_ONEWIRE, _) => Command::DiscOneWire(params),
        (SUBCOMMAND_SET_IP_SUB_GW, m) => Command::SetNetIpSubGate(
            params,
            Ipv4Addr::from_str(m.unwrap().value_of(ARG_IP_ADDR).unwrap()).unwrap(),
            Ipv4Addr::from_str(m.unwrap().value_of(ARG_SUBNET).unwrap()).unwrap(),
            Ipv4Addr::from_str(m.unwrap().value_of(ARG_GATEWAY).unwrap()).unwrap(),
        ),
        (SUBCOMMAND_SET_MAC, m) => Command::SetNetMac(params, {
            let mac = m.unwrap().value_of(ARG_MAC).unwrap();
            [
                u8::from_str_radix(&mac[0..2], 16).unwrap(),
                u8::from_str_radix(&mac[3..5], 16).unwrap(),
                u8::from_str_radix(&mac[6..8], 16).unwrap(),
                u8::from_str_radix(&mac[9..11], 16).unwrap(),
                u8::from_str_radix(&mac[12..14], 16).unwrap(),
                u8::from_str_radix(&mac[15..17], 16).unwrap(),
            ]
        }),
        _ => panic!("SubCommand not specified"),
    }
}
