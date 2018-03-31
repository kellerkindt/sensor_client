#![feature(duration_extras)]

extern crate byteorder;
extern crate random;

extern crate onewire;
extern crate sensor_common;


use byteorder::ByteOrder;
use byteorder::NetworkEndian;

use onewire::Device;
use sensor_common::*;

use std::io;
use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::net::ToSocketAddrs;
use std::time::Duration;

use random::Source;

use std::u8;
use std::time::Instant;

enum Value {
    OneWireDevices(Vec<Device>),
    OneWireDeviceValuePairs(Vec<(Device, f32)>),
}

fn main() {
    if std::env::args().len() == 2 {
        let mut args = std::env::args().collect::<Vec<String>>();
        let mut socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(1000)));

        let mut random = random::default();
        let mut buffer = [0; 2048];
        let mut error_code = 1;

        'main: for _ in 0..5 {
            let size = Request::DiscoverAllOnBus(random.read::<u8>(), Bus::OneWire).write(&mut &mut buffer[..]).unwrap();

            let request_time = Instant::now();
            socket.send_to(&buffer[..size], &args[1]).expect("Failed to send");

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
                        }
                        error_code = 0;
                        break 'main;
                    },
                    _ => {},
                };
            }
        }
        std::process::exit(error_code);

    } else if std::env::args().len() > 2 {
        let mut args = std::env::args().collect::<Vec<String>>();
        let mut socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut random = random::default();
        let mut buffer = [0; 2048];
        let mut error_code = 1;

        let address = &args[1];

        socket.set_read_timeout(Some(Duration::from_millis(1000)));

        match &args[2] as &str {
            "version" => {
                for _ in 0..5 {
                    let request = Request::RetrieveVersionInformation(random.read::<u8>());
                    if let Ok((response, data)) = send_wait_response(&mut socket, address, &request) {
                        if let Response::Ok(_, Format::ValueOnly(Type::String(_))) = response {
                            println!("Version: {}", String::from_utf8_lossy(&data));
                            error_code = 0;

                        } else {
                            println!("Error: {:?}", response);
                            error_code = 2;
                        }

                        break;
                    }
                }
            },
            "get-network-conf" => {
                for _ in 0..5 {
                    let request = Request::RetrieveNetworkConfiguration(random.read::<u8>());
                    if let Ok((response, data)) = send_wait_response(&mut socket, address, &request) {
                        // 18 = 6 + 3*4
                        if let Response::Ok(_, Format::ValueOnly(Type::Bytes(18))) = response {
                            println!("MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", data[0], data[1], data[2], data[3], data[4], data[5]);
                            println!();
                            println!("IP:      {:}.{:}.{:}.{:}", data[ 6], data[ 7], data[ 8], data[ 9]);
                            println!("Subnet:  {:}.{:}.{:}.{:}", data[10], data[11], data[12], data[13]);
                            println!("Gateway: {:}.{:}.{:}.{:}", data[14], data[15], data[16], data[17]);
                            error_code = 0;

                        } else {
                            println!("Error: {:?}", response);
                            error_code = 2;
                        }

                        break;
                    }
                }
            },
            "set-network-mac" => {
                if args.len() >= 4 {
                    let arg = args[3].clone();
                    let mac = [
                        u8::from_str_radix(&arg[0..2], 16).unwrap(),
                        u8::from_str_radix(&arg[3..5], 16).unwrap(),
                        u8::from_str_radix(&arg[6..8], 16).unwrap(),
                        u8::from_str_radix(&arg[9..11], 16).unwrap(),
                        u8::from_str_radix(&arg[12..14], 16).unwrap(),
                        u8::from_str_radix(&arg[15..17], 16).unwrap(),
                    ];

                    for _ in 0..5 {
                        let request = Request::SetNetworkMac(random.read::<u8>(), mac);
                        if let Ok((response, data)) = send_wait_response(&mut socket, address, &request) {
                            if let Response::Ok(_, Format::Empty) = response {
                                error_code = 0;

                            } else {
                                println!("Error: {:?}", response);
                                error_code = 2;
                            }
                            break;
                        }
                    }
                } else {
                    println!("Missing mac address");
                    error_code = 3;
                }
            },
            "set-network-ip-subnet-gateway" => {
                if args.len() >= 6 {
                    use std::str::FromStr;
                    let ip      = Ipv4Addr::from_str(&args[3]).unwrap();
                    let subnet  = Ipv4Addr::from_str(&args[4]).unwrap();
                    let gateway = Ipv4Addr::from_str(&args[5]).unwrap();


                    for _ in 0..5 {
                        let request = Request::SetNetworkIpSubnetGateway(random.read::<u8>(), ip.octets(), subnet.octets(), gateway.octets());
                        if let Ok((response, data)) = send_wait_response(&mut socket, address, &request) {
                            if let Response::Ok(_, Format::Empty) = response {
                                error_code = 0;

                            } else {
                                println!("Error: {:?}", response);
                                error_code = 2;
                            }
                            break;
                        }
                    }


                } else {
                    println!("Required <ip> <subnet> <gateway>");
                    error_code = 3;
                }
            }
            _ => {
                let mut devices = Vec::new();
                for i in 2..std::env::args().len() {
                    let arg = &args[i];
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
                    }
                }




                'main: for _ in 0..5 {
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
                    socket.send_to(&buffer[..size], address).expect("Failed to send");

                    if let Ok((amt, src)) = socket.recv_from(&mut buffer) {
                        let mut reader = &mut &buffer[..amt];
                        let response = Response::read(reader);
                        let duration = Instant::now().duration_since(request_time);
                        // println!("  Received from {}: {}bytes, {:?}, {}ms", src, amt, response, duration.as_secs() * 1000 + duration.subsec_millis() as u64);
                        match response {
                            Ok(response) => {
                                if let Err(e) = handle_response(response, reader, true) {
                                    println!("  Handling failed: {:?}", e);
                                }
                                error_code = 0;
                                break 'main;
                            },
                            _ => {},
                        };
                    }
                }
            },
        };



        std::process::exit(error_code);
    } else {
        default();
    }
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

fn default() {
    let mut socket = UdpSocket::bind("0.0.0.0:0").unwrap();

    // Receives a single datagram message on the socket. If `buf` is too small to hold
    // the message, it will be cut off.

    socket.set_read_timeout(Some(Duration::from_millis(1100)));
    let mut random = random::default();
    let mut buffer = [0; 2048];

    {
        let size = Request::DiscoverAllOnBus(random.read::<u8>(), Bus::OneWire).write(&mut &mut buffer[..]).unwrap();
        socket.send_to(&buffer[..size], "192.168.3.222:51").expect("Failed to send");
    }

    loop {

        let request = Request::ReadAllOnBus(random.read::<u8>(), Bus::OneWire);
        let size = request.write(&mut &mut buffer[..]).unwrap();


        println!("Requesting");
        let request_time = Instant::now();
        socket.send_to(&buffer[..size], "192.168.3.222:51").expect("Failed to send");

        if let Ok((amt, src)) = socket.recv_from(&mut buffer) {
            let mut reader = &mut &buffer[..amt];
            let response = Response::read(reader);
            let duration = Instant::now().duration_since(request_time);
            println!("  Received from {}: {}bytes, {:?}, {}ms", src, amt, response, duration.as_secs() * 1000 + duration.subsec_millis() as u64);
            match response {
                Ok(response) => {
                    if let Err(e) = handle_response(response, reader, false) {
                        println!("  Handling failed: {:?}", e);
                    }
                },
                _ => {},
            };
        }
    }
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