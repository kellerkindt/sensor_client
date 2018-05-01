#![feature(duration_extras)]

extern crate clap;
extern crate byteorder;
extern crate random;

extern crate onewire;
extern crate sensor_common;


use byteorder::ByteOrder;
use byteorder::NetworkEndian;

use onewire::Device;
use sensor_common::*;

use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::time::Duration;

use random::Source;

use std::u8;
use std::time::Instant;

enum Value {
    OneWireDevices(Vec<Device>),
    OneWireDeviceValuePairs(Vec<(Device, f32)>),
}

const EXIT_CODE_SUCCESSFUL : i32 = 0;
const EXIT_CODE_UNREACHABLE : i32 = -1;
const EXIT_CODE_DEVICE_ERROR : i32 = -2;
const EXIT_CODE_INVALID_PARAM : i32 = 1;

fn main() {
    let command = read_command();

    let mut socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(1000)));

    let mut random = random::default();
    let mut buffer = [0; 2048];
    let mut exit_code = EXIT_CODE_UNREACHABLE;

    for _ in 0..5 {
        if match command {
            Command::GetVersion(ip, port) => {
                let request = Request::RetrieveVersionInformation(random.read::<u8>());
                if let Ok((response, data)) = send_wait_response(&mut socket, SocketAddr::new(IpAddr::V4(ip), port), &request) {
                    if let Response::Ok(_, Format::ValueOnly(Type::String(_))) = response {
                        println!("Version: {}", String::from_utf8_lossy(&data));
                        true

                    } else {
                        println!("Error: {:?}", response);
                        exit_code = EXIT_CODE_DEVICE_ERROR;
                        break;
                    }
                } else {
                    false
                }
            },
            Command::GetNetConf(ip, port) => {
                let request = Request::RetrieveNetworkConfiguration(random.read::<u8>());
                if let Ok((response, data)) = send_wait_response(&mut socket, SocketAddr::new(IpAddr::V4(ip), port), &request) {
                    // 18 = 6 + 3*4
                    if let Response::Ok(_, Format::ValueOnly(Type::Bytes(18))) = response {
                        println!("MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", data[0], data[1], data[2], data[3], data[4], data[5]);
                        println!();
                        println!("IP:      {:}.{:}.{:}.{:}", data[ 6], data[ 7], data[ 8], data[ 9]);
                        println!("Subnet:  {:}.{:}.{:}.{:}", data[10], data[11], data[12], data[13]);
                        println!("Gateway: {:}.{:}.{:}.{:}", data[14], data[15], data[16], data[17]);
                        exit_code = 0;

                    } else {
                        println!("Error: {:?}", response);
                        exit_code = EXIT_CODE_DEVICE_ERROR;
                        break;
                    }
                    true
                } else {
                    false
                }
            },
            Command::ReadOneWire(ip, port, ref addresses) => {
                let mut devices = Vec::new();
                for arg in addresses.iter() {
                    if arg.len() == 23 {
                        devices.push(Device {
                            address: [
                                u8::from_str_radix(&arg[0..2], 16).unwrap(),
                                u8::from_str_radix(&arg[3..5], 16).unwrap(),
                                u8::from_str_radix(&arg[6..8], 16).unwrap(),
                                u8::from_str_radix(&arg[9..11], 16).unwrap(),
                                u8::from_str_radix(&arg[12..14], 16).unwrap(),
                                u8::from_str_radix(&arg[15..17], 16).unwrap(),
                                u8::from_str_radix(&arg[18..20], 16).unwrap(),
                                u8::from_str_radix(&arg[21..23], 16).unwrap(),
                            ]
                        })
                    } else {
                        println!("Invalid OneWire address: {}", arg);
                        exit_code = EXIT_CODE_INVALID_PARAM;
                        break;
                    }
                }


                let size = Request::ReadSpecified(random.read::<u8>(), Bus::OneWire).write(&mut &mut buffer[..]).unwrap();
                let size = {
                    let mut pos = size;
                    for device in &devices {
                        let sub_buffer = &mut buffer[pos..(pos+onewire::ADDRESS_BYTES as usize)];
                        sub_buffer.copy_from_slice(&device.address);
                        pos += onewire::ADDRESS_BYTES as usize;
                    }
                    pos
                };

                let request_time = Instant::now();
                socket.send_to(&buffer[..size], SocketAddr::new(IpAddr::V4(ip), port)).expect("Failed to send");

                if let Ok((amt, src)) = socket.recv_from(&mut buffer) {
                    let mut reader = &mut &buffer[..amt];
                    let response = Response::read(reader);
                    let duration = Instant::now().duration_since(request_time);
                    // println!("  Received from {}: {}bytes, {:?}, {}ms", src, amt, response, duration.as_secs() * 1000 + duration.subsec_millis() as u64);
                    match response {
                        Ok(response) => {
                            if let Err(e) = handle_response(response, reader, true) {
                                exit_code = EXIT_CODE_DEVICE_ERROR;
                                println!("  Handling failed: {:?}", e);
                                false
                            } else {
                                true
                            }
                        },
                        _ => {
                            exit_code = EXIT_CODE_DEVICE_ERROR;
                            false
                        },
                    }
                } else {
                    exit_code = EXIT_CODE_DEVICE_ERROR;
                    false
                }
            }
            Command::DiscOneWire(ip, port) => {
                let size = Request::DiscoverAllOnBus(random.read::<u8>(), Bus::OneWire).write(&mut &mut buffer[..]).unwrap();

                let request_time = Instant::now();
                socket.send_to(&buffer[..size], SocketAddr::new(IpAddr::V4(ip), port)).expect("Failed to send");

                if let Ok((amt, src)) = socket.recv_from(&mut buffer) {
                    let mut reader = &mut &buffer[..amt];
                    let response = Response::read(reader);
                    let duration = Instant::now().duration_since(request_time);
                    // println!("  Received from {}: {}bytes, {:?}, {}ms", src, amt, response, duration.as_secs() * 1000 + duration.subsec_millis() as u64);
                    match response {
                        Ok(response) => {
                            let response_size = reader.available();
                            if let Err(e) = handle_response(response, reader, true) {
                                println!("  Handling(size: {}) failed: {:?}", response_size, e);
                                exit_code = EXIT_CODE_DEVICE_ERROR;
                                break;
                            } else {
                                true
                            }
                        },
                        _ => {
                            exit_code = EXIT_CODE_DEVICE_ERROR;
                            break;
                        },
                    }
                } else {
                    false
                }
            }
            Command::SetNetIpSubGate(ip, port, new_ip, subnet, gateway) => {
                let request = Request::SetNetworkIpSubnetGateway(random.read::<u8>(), new_ip.octets(), subnet.octets(), gateway.octets());
                if let Ok((response, data)) = send_wait_response(&mut socket, SocketAddr::new(IpAddr::V4(ip), port), &request) {
                    if let Response::Ok(_, Format::Empty) = response {
                        true

                    } else {
                        println!("Error: {:?}", response);
                        exit_code = EXIT_CODE_DEVICE_ERROR;
                        break
                    }
                } else {
                    false
                }
            }
            Command::SetNetMac(ip, port, mac) => {
                println!("Sending {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                let request = Request::SetNetworkMac(random.read::<u8>(), mac);
                if let Ok((response, data)) = send_wait_response(&mut socket, SocketAddr::new(IpAddr::V4(ip), port), &request) {
                    if let Response::Ok(_, Format::Empty) = response {
                        true

                    } else {
                        println!("Error: {:?}", response);
                        exit_code = EXIT_CODE_DEVICE_ERROR;
                        break
                    }
                } else {
                    false
                }
            }
        } {
            exit_code = EXIT_CODE_SUCCESSFUL;
            break;
        } else {
            // println!("No response received...");
        }
    }

    std::process::exit(exit_code);
}

fn send_wait_response<A: ToSocketAddrs>(udp: &mut UdpSocket, address: A, request: &Request) -> Result<(Response, Vec<u8>), io::Error> {
    let mut buffer = [0u8; 2048];
    let size = request.write(&mut &mut buffer[..]).unwrap();
    udp.send_to(&buffer[..size], address)?;
    let (amt, src) = udp.recv_from(&mut buffer)?;
    let (response, offset) = {
        let mut reader = &mut &buffer[..amt];
        let before = reader.available();
        let response = Response::read(reader).unwrap();
        (response, before - reader.available())
    };
    Ok((response, Vec::from(&buffer[offset..])))
}


fn handle_response(response: Response, reader: &mut Read, silent: bool) -> Result<Value, Error> {
    Ok(match response {
        Response::Ok(id, format) if format == Format::AddressValuePairs(Type::Bytes(8), Type::F32) => {
            let mut devices = Vec::new();
            while reader.available() > 0 {
                let device = Device {
                    address: [
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                    ]
                };
                let temp = NetworkEndian::read_f32(&[reader.read_u8()?, reader.read_u8()?, reader.read_u8()?, reader.read_u8()?]);

                if !silent {
                    print!("    {:02x}", device.address[0]);
                    for i in 0..7 {
                        print!(":{:02x}", device.address[1+i]);
                    }
                    println!(" with {:.4}°C", temp);
                } else {
                    println!("{}", temp);
                }
                devices.push((device, temp));
            }
            Value::OneWireDeviceValuePairs(devices)
        },
        Response::Ok(id, format) if format == Format::AddressOnly(Type::Bytes(8)) => {
            let mut devices = Vec::new();
            while reader.available() > 0 {
                let device = Device {
                    address: [
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                        reader.read_u8()?,
                    ]
                };

                print!("    {:02x}", device.address[0]);
                for i in 0..7 {
                    print!(":{:02x}", device.address[1+i]);
                }
                println!();
                devices.push(device);
            }
            Value::OneWireDevices(devices)
        }
        _ => return Err(Error::UnknownTypeIdentifier),
    })
}

use std::str::FromStr;
use clap::{Arg, App, SubCommand, AppSettings};

const ARG_IP_ADDR : &'static str = "ip";
const ARG_SUBNET : &'static str = "subnet";
const ARG_GATEWAY : &'static str = "gateway";
const ARG_MAC : &'static str = "mac";
const ARG_PORT : &'static str = "port";
const ARG_ONEWIRE_ADDR : &'static str = "onewire-addr";

const SUBCOMMAND_GET_VERSION : &'static str = "get-version";
const SUBCOMMAND_GET_NET_CONF : &'static str = "get-network-config";
const SUBCOMMAND_READ_ONEWIRE : &'static str = "onewire-read";
const SUBCOMMAND_DISC_ONEWIRE : &'static str = "onewire-discover";
const SUBCOMMAND_SET_IP_SUB_GW : &'static str = "set-network-ip-subnet-gateway";
const SUBCOMMAND_SET_MAC : &'static str = "set-network-mac";

enum Command {
    GetVersion(Ipv4Addr, u16),
    GetNetConf(Ipv4Addr, u16),
    ReadOneWire(Ipv4Addr, u16, Vec<String>),
    DiscOneWire(Ipv4Addr, u16),
    SetNetIpSubGate(Ipv4Addr, u16, Ipv4Addr, Ipv4Addr, Ipv4Addr),
    SetNetMac(Ipv4Addr, u16, [u8; 6]),
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
        .arg(Arg::with_name(ARG_IP_ADDR)
            .short("i")
            .long("ip")
            .value_name("IP_ADDRESS")
            .multiple(false)
            .required(true)
            .index(1)
            .help("Ip address of the device")
            .takes_value(true)
        )
        .arg(Arg::with_name(ARG_PORT)
            .short("p")
            .long("port")
            .value_name("PORT_NUMBER")
            .multiple(false)
            .required(false)
            .index(2)
            .help("The port for the device")
            .takes_value(true)
            .default_value("51")
        )
        .subcommand(SubCommand::with_name(SUBCOMMAND_GET_VERSION)
            .about("Reads the version from the specified device")
        )
        .subcommand(SubCommand::with_name(SUBCOMMAND_GET_NET_CONF)
            .alias("get-net-conf")
            .alias("get-network-conf")
            .alias("get-net-config")
            .about("Reads the network configuration from the specified device")
        )
        .subcommand(SubCommand::with_name(SUBCOMMAND_READ_ONEWIRE)
            .about("Lets the specified device read values from the specified OneWire sensors")
            .arg(Arg::with_name(ARG_ONEWIRE_ADDR)
                .required(true)
                .multiple(true)
                .value_name("SENSOR_ADDRESS")
                .help("OneWire address")
            )
        )
        .subcommand(SubCommand::with_name(SUBCOMMAND_DISC_ONEWIRE)
            .about("Lets the specified device discover all connected OneWire sensors")
        )
        .subcommand(SubCommand::with_name(SUBCOMMAND_SET_IP_SUB_GW)
            .about("Reconfigures the devices' ip, subnet and gateway addresses")
            .arg(Arg::with_name(ARG_IP_ADDR)
                .required(true)
                .index(1)
                .takes_value(true)
                .value_name("IP")
                .help("The new ip address for the device")
            )
            .arg(Arg::with_name(ARG_SUBNET)
                .required(true)
                .index(2)
                .takes_value(true)
                .value_name("SUBNET")
                .help("The new subnet address of the device")
            )
            .arg(Arg::with_name(ARG_GATEWAY)
                .required(true)
                .index(3)
                .takes_value(true)
                .value_name("GATEWAY")
                .help("The new gateway address of the device")
            )
        )
        .subcommand(SubCommand::with_name(SUBCOMMAND_SET_MAC)
            .about("Reconfigures the devices' mac address")
            .arg(Arg::with_name(ARG_MAC)
                .required(true)
                .index(1)
                .takes_value(true)
                .value_name("MAC")
                .help("The new mac address for the device")
            )
        )
        .get_matches();

    let ip = Ipv4Addr::from_str(matches.value_of(ARG_IP_ADDR).unwrap()).unwrap();
    let port = matches.value_of(ARG_PORT).unwrap().parse::<u16>().unwrap();

    match matches.subcommand() {
        (SUBCOMMAND_GET_VERSION, _) => Command::GetVersion(ip, port),
        (SUBCOMMAND_GET_NET_CONF, _) => Command::GetNetConf(ip, port),
        (SUBCOMMAND_READ_ONEWIRE, m) => Command::ReadOneWire(
            ip,
            port,
            m.unwrap().values_of_lossy(ARG_ONEWIRE_ADDR).unwrap()
        ),
        (SUBCOMMAND_DISC_ONEWIRE, _) => Command::DiscOneWire(ip, port),
        (SUBCOMMAND_SET_IP_SUB_GW, m) => Command::SetNetIpSubGate(
            ip,
            port,
            Ipv4Addr::from_str(m.unwrap().value_of(ARG_IP_ADDR).unwrap()).unwrap(),
            Ipv4Addr::from_str(m.unwrap().value_of(ARG_SUBNET).unwrap()).unwrap(),
            Ipv4Addr::from_str(m.unwrap().value_of(ARG_GATEWAY).unwrap()).unwrap(),
        ),
        (SUBCOMMAND_SET_MAC, m) => Command::SetNetMac(
            ip,
            port,
            {
                let mac = m.unwrap().value_of(ARG_MAC).unwrap();
                [
                    u8::from_str_radix(&mac[0..2], 16).unwrap(),
                    u8::from_str_radix(&mac[3..5], 16).unwrap(),
                    u8::from_str_radix(&mac[6..8], 16).unwrap(),
                    u8::from_str_radix(&mac[9..11], 16).unwrap(),
                    u8::from_str_radix(&mac[12..14], 16).unwrap(),
                    u8::from_str_radix(&mac[15..17], 16).unwrap(),
                ]
            }
        ),
        _ => panic!("SubCommand not specified")
    }
}