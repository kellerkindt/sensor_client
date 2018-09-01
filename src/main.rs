#![feature(duration_extras)]

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
use std::net::IpAddr;
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
            },
        }
    }
}

fn main() {
    match handle_command(read_command(), 5) {
        Err(e) => {
            eprintln!("{}", e.err_msg());
            std::process::exit(e.exit_code());
        },
        Ok(_) => std::process::exit(0),
    }
}

fn print_binary(target: &mut String, binary: &[u8]) {
    target.push_str(" ------+--------------------------+--------------------------+-----------\n");
    for i in 0..(binary.len() / 8) + 1 {
        target.push_str(&format!("  {:3}  : ", (i+1)));
        let from = i*8;
        let to = (i+1) * 8;
        for n in from..to.min(binary.len()) {
            target.push_str(&format!("{:02x} ", binary[n]));
        }
        for _ in to.min(binary.len())..to {
            target.push_str("   ");
        }
        target.push_str(" : ");
        for n in from..to.min(binary.len()) {
            target.push_str(&format!("{:2} ", binary[n]));
        }
        for _ in to.min(binary.len())..to {
            target.push_str("   ");
        }
        target.push_str(" : ");
        for n in from..to.min(binary.len()) {
            target.push_str(&format!("{} ", binary[n] as char));
        }
        target.push_str("\n");
    }
}

fn handle_command(command: Command, max_retries: usize) -> Result<(), CommandError> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(1000)))?;

    let mut random = random::default();
    let mut buffer = [0; 2048];

    let address = SocketAddr::new(IpAddr::V4(*command.ip()), command.port());

    for _ in 0..max_retries {
        let request = command.new_request(random.read::<u8>());
        let request_size = {
            let write = &mut &mut buffer[..] as &mut Write;
            request.write(write)? + command.append_payload(write)?
        };

        socket.send_to(&buffer[..request_size], address)?;
        match socket.recv_from(&mut buffer[..]) {
            Ok((size, address)) => {
                let read = &mut &buffer[..size] as &mut Read;
                let response = Response::read(read)?;

                if address.ip().ne(&IpAddr::V4(*command.ip())) {
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
                            Format::ValueOnly(Type::Bytes(n)) => {
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

                                        println!("Frequency: {} MHz", frequency / 1_000_000);
                                        println!("Uptime: {} ticks / {} s", uptime, uptime / frequency);
                                        println!("CPUID");
                                        println!(" - Implementer: {:02x}", data[12]);
                                        println!(" - Variant:     {:02x}", data[13]);
                                        println!(
                                            " - PartNumber:  {:04x}",
                                            NetworkEndian::read_u16(&data[14..])
                                        );
                                        println!(" - Revision:    {:02x}", data[16]);
                                        println!("MAGIC_EEPROM_CRC_START: 0x{:02x} ({})", data[17], data[17]);
                                    }
                                    if n > 18 {
                                        let mut binary = String::new();
                                        print_binary(&mut binary, &data[14..n as usize]);
                                        println!("  Further information were provided:");
                                        println!("{}", binary);
                                    }
                                }
                            }
                            Format::ValueOnly(Type::Bytes(18)) => {
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
                            Format::ValueOnly(format_type) => while read.available() > 0 {
                                print_generic_format_type(format_type, read, false)?;
                                println!();
                            },
                            Format::AddressOnly(format_type) => while read.available() > 0 {
                                print_generic_format_type(format_type, read, true)?;
                                println!();
                            },
                            Format::AddressValuePairs(address_type, value_type) => {
                                while read.available() > 0 {
                                    print_generic_format_type(address_type, read, true)?;
                                    print!(" ");
                                    print_generic_format_type(value_type, read, false)?;
                                    println!();
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

fn print_generic_format_type(
    format_type: Type,
    read: &mut Read,
    is_address: bool,
) -> Result<(), CommandError> {
    match format_type {
        Type::F32 => print!(
            "{}",
            NetworkEndian::read_f32(&[
                read.read_u8()?,
                read.read_u8()?,
                read.read_u8()?,
                read.read_u8()?,
            ])
        ),
        Type::Bytes(len) => {
            for i in 0..len {
                if i > 0 && is_address {
                    print!(":");
                }
                print!("{:02x}", read.read_u8()?);
            }
        }
        Type::String(len) => {
            let len = len as usize;
            let mut vec = Vec::with_capacity(len);
            for _ in 0..len {
                vec.push(read.read_u8()?);
            }
            print!("{}", String::from_utf8_lossy(&vec[..len]));
        }
    }
    Ok(())
}

use clap::{App, AppSettings, Arg, SubCommand};
use std::str::FromStr;

const ARG_IP_ADDR: &'static str = "ip";
const ARG_SUBNET: &'static str = "subnet";
const ARG_GATEWAY: &'static str = "gateway";
const ARG_MAC: &'static str = "mac";
const ARG_PORT: &'static str = "port";
const ARG_ONEWIRE_ADDR: &'static str = "onewire-addr";
const ARG_BUS_ADDR: &'static str = "bus-addr";

const SUBCOMMAND_GET_VERSION: &'static str = "get-version";
const SUBCOMMAND_GET_NET_CONF: &'static str = "get-network-config";
const SUBCOMMAND_GET_INFO: &'static str = "get-info";
const SUBCOMMAND_READ_ONEWIRE: &'static str = "onewire-read";
const SUBCOMMAND_READ_CUSTOM_BUS: &'static str = "custom-read";
const SUBCOMMAND_DISC_ONEWIRE: &'static str = "onewire-discover";
const SUBCOMMAND_SET_IP_SUB_GW: &'static str = "set-network-ip-subnet-gateway";
const SUBCOMMAND_SET_MAC: &'static str = "set-network-mac";

#[derive(Clone, Debug)]
enum Command {
    GetVersion(Ipv4Addr, u16),
    GetNetConf(Ipv4Addr, u16),
    GetDevInfo(Ipv4Addr, u16),
    ReadOneWire(Ipv4Addr, u16, Vec<Device>),
    ReadBus(Ipv4Addr, u16, u8),
    DiscOneWire(Ipv4Addr, u16),
    SetNetIpSubGate(Ipv4Addr, u16, Ipv4Addr, Ipv4Addr, Ipv4Addr),
    SetNetMac(Ipv4Addr, u16, [u8; 6]),
}

impl Command {
    pub fn ip(&self) -> &Ipv4Addr {
        match self {
            Command::GetVersion(ip, _) => &ip,
            Command::GetNetConf(ip, _) => &ip,
            Command::GetDevInfo(ip, _) => &ip,
            Command::ReadOneWire(ip, _, _) => &ip,
            Command::ReadBus(ip, _, _) => &ip,
            Command::DiscOneWire(ip, _) => &ip,
            Command::SetNetIpSubGate(ip, _, _, _, _) => &ip,
            Command::SetNetMac(ip, _, _) => &ip,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Command::GetVersion(_, port) => *port,
            Command::GetNetConf(_, port) => *port,
            Command::GetDevInfo(_, port) => *port,
            Command::ReadOneWire(_, port, _) => *port,
            Command::ReadBus(_, port, _) => *port,
            Command::DiscOneWire(_, port) => *port,
            Command::SetNetIpSubGate(_, port, _, _, _) => *port,
            Command::SetNetMac(_, port, _) => *port,
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
            Command::GetVersion(_, _) => Request::RetrieveVersionInformation(id),
            Command::GetNetConf(_, _) => Request::RetrieveNetworkConfiguration(id),
            Command::GetDevInfo(_, _) => Request::RetrieveDeviceInformation(id),
            Command::ReadOneWire(_, _, _) => Request::ReadSpecified(id, Bus::OneWire),
            Command::ReadBus(_, _, bus) => Request::ReadSpecified(id, Bus::Custom(*bus)),
            Command::DiscOneWire(_, _) => Request::DiscoverAllOnBus(id, Bus::OneWire),
            Command::SetNetIpSubGate(_, _, ip, sub, gate) => {
                Request::SetNetworkIpSubnetGateway(id, ip.octets(), sub.octets(), gate.octets())
            }
            Command::SetNetMac(_, _, mac) => Request::SetNetworkMac(id, mac.clone()),
        }
    }

    fn append_payload(&self, writer: &mut Write) -> Result<usize, Error> {
        Ok(match self {
            Command::GetVersion(_, _) => 0,
            Command::GetNetConf(_, _) => 0,
            Command::GetDevInfo(_, _) => 0,
            Command::ReadOneWire(_, _, devices) => {
                let mut count = 0;
                for device in devices.iter() {
                    count += writer.write_all(&device.address)?;
                }
                count
            }
            Command::ReadBus(_, _, _) => 0,
            Command::DiscOneWire(_, _) => 0,
            Command::SetNetIpSubGate(_, _, _, _, _) => 0,
            Command::SetNetMac(_, _, _) => 0,
        })
    }
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
            SubCommand::with_name(SUBCOMMAND_READ_ONEWIRE)
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

    match matches.subcommand() {
        (SUBCOMMAND_GET_VERSION, _) => Command::GetVersion(ip, port),
        (SUBCOMMAND_GET_NET_CONF, _) => Command::GetNetConf(ip, port),
        (SUBCOMMAND_GET_INFO, _) => Command::GetDevInfo(ip, port),
        (SUBCOMMAND_READ_ONEWIRE, m) => Command::ReadOneWire(
            ip,
            port,
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
        (SUBCOMMAND_READ_CUSTOM_BUS, m) => Command::ReadBus(
            ip,
            port,
            (&m.unwrap().value_of(ARG_BUS_ADDR).unwrap() as &str)
                .parse::<u8>()
                .unwrap(),
        ),
        (SUBCOMMAND_DISC_ONEWIRE, _) => Command::DiscOneWire(ip, port),
        (SUBCOMMAND_SET_IP_SUB_GW, m) => Command::SetNetIpSubGate(
            ip,
            port,
            Ipv4Addr::from_str(m.unwrap().value_of(ARG_IP_ADDR).unwrap()).unwrap(),
            Ipv4Addr::from_str(m.unwrap().value_of(ARG_SUBNET).unwrap()).unwrap(),
            Ipv4Addr::from_str(m.unwrap().value_of(ARG_GATEWAY).unwrap()).unwrap(),
        ),
        (SUBCOMMAND_SET_MAC, m) => Command::SetNetMac(ip, port, {
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
