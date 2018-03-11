extern crate byteorder;
extern crate random;

extern crate sensor_common;


use byteorder::ByteOrder;
use byteorder::LittleEndian;

use sensor_common::*;

use std::net::UdpSocket;
use std::time::Duration;

use random::Source;

fn main() {
    let mut socket = UdpSocket::bind("0.0.0.0:5354").unwrap();

    // Receives a single datagram message on the socket. If `buf` is too small to hold
    // the message, it will be cut off.

    socket.set_read_timeout(Some(Duration::from_millis(900)));
    let mut random = random::default();

    loop {
        let mut buf = [0; 2048];

        let request = Request::ReadAllOnBus(random.read::<u8>(), Bus::OneWire);
        let size = request.write(&mut &mut buf[..]).unwrap();


        println!("Requesting");
        socket.send_to(&buf[..size], "192.168.3.222:51").expect("Failed to send");

        if let Ok((amt, src)) = socket.recv_from(&mut buf) {
            let mut reader = &mut &buf[..amt];
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
            /*
            if amt >= 4 {
                let temp = LittleEndian::read_f32(&buf);
                println!("   Temperatur: {}°C", temp);
            } else {
                print!("    ");
                for b in &buf[..amt] {
                    print!("{:x} ", b);
                }
                println!();
            }*/
        }
    }
}


fn handle_response(response: Response, reader: &mut Read) -> Result<(), Error> {
    match response {
        Response::Ok(id, format) if format == Format::AddressValuePairs(Type::Array(8), Type::F32) => {
            while reader.available() > 0 {
                print!("    {:02x}", reader.read_u8()?);
                for _ in 0..7 {
                    print!(":{:02x}", reader.read_u8()?);
                }
                let temp = LittleEndian::read_f32(&[reader.read_u8()?, reader.read_u8()?, reader.read_u8()?, reader.read_u8()?]);
                println!(" with {:.4}°C", temp);
            }
        },
        _ => {},
    };
    Ok(())
}