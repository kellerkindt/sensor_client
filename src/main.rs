#![feature(duration_extras)]

extern crate byteorder;
extern crate random;

extern crate onewire;
extern crate sensor_common;


use byteorder::ByteOrder;
use byteorder::NetworkEndian;

use onewire::Device;
use sensor_common::*;

use std::net::UdpSocket;
use std::time::Duration;

use random::Source;

use std::u8;
use std::time::Instant;

enum Value {
    OneWireDevices(Vec<Device>),
    OneWireDeviceValuePairs(Vec<(Device, f32)>),
}

fn main() {
    if std::env::args().len() > 1 {
        let mut devices = Vec::new();
        let mut args = std::env::args().collect::<Vec<String>>();
        for i in 1..std::env::args().len() {
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

        let mut socket = UdpSocket::bind("0.0.0.0:5354").unwrap();

        socket.set_read_timeout(Some(Duration::from_millis(5000)));

        let mut random = random::default();
        let mut buffer = [0; 2048];

        loop {
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
                        if let Err(e) = handle_response(response, reader) {
                            println!("  Handling failed: {:?}", e);
                        }
                    },
                    _ => {},
                };
            }
        }

        println!("{:?}", devices);
    } else {
        default();
    }
}

fn default() {
    let mut socket = UdpSocket::bind("0.0.0.0:5354").unwrap();

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
        socket.send_to(&buffer[..size], "192.168.3.222:51").expect("Failed to send");

        if let Ok((amt, src)) = socket.recv_from(&mut buffer) {
            let mut reader = &mut &buffer[..amt];
            let response = Response::read(reader);
            println!("  Received from {}: {}, {:?}", src, amt, response);
            match response {
                Ok(response) => {
                    if let Err(e) = handle_response(response, reader) {
                        println!("  Handling failed: {:?}", e);
                    }
                },
                _ => {},
            };
        }
    }
}


fn handle_response(response: Response, reader: &mut Read) -> Result<Value, Error> {
    Ok(match response {
        Response::Ok(id, format) if format == Format::AddressValuePairs(Type::Array(8), Type::F32) => {
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
                let temp = NetworkEndian::read_f32(&[reader.read_u8()?, reader.read_u8()?, reader.read_u8()?, reader.read_u8()?]);
                println!(" with {:.4}°C", temp);
                devices.push((device, temp));
            }
            Value::OneWireDeviceValuePairs(devices)
        },
        Response::Ok(id, format) if format == Format::AddressOnly(Type::Array(8)) => {
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