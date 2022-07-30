use clap::{AppSettings, Parser, Subcommand};
use onewire::Device;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Parser)]
#[clap(version = env!("CARGO_PKG_VERSION"), author = env!("CARGO_PKG_AUTHORS"))]
#[clap(setting = AppSettings::SubcommandRequiredElseHelp)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::GlobalVersion)]
// #[clap(setting = AppSettings::VersionlessSubcommands)]
pub struct Args {
    /// The ip of the target device
    pub ip: Ipv4Addr,
    /// The port of the target device
    #[clap(default_value = "51")]
    pub port: u16,
    /// Prints no address of received values
    #[clap(long)]
    pub no_address: bool,
    /// How many times the request should be sent until a timout is considered
    #[clap(long, default_value = "5")]
    pub max_retries: usize,
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Reads the device's version
    #[clap(alias = "version")]
    GetVersion(GetVersion),
    /// Requests and displays general device information
    #[clap(alias = "info")]
    GetInfo(GetInfo),
    /// Reads the device's network configuration
    #[clap(alias = "net")]
    #[clap(alias = "network")]
    #[clap(alias = "get-net")]
    #[clap(alias = "get-net-conf")]
    #[clap(alias = "get-net-config")]
    #[clap(alias = "get-network")]
    #[clap(alias = "get-network-conf")]
    #[clap(alias = "get-network-config")]
    GetNetInfo(GetNetInfo),
    /// Retrieves and (if any) displays the error dump
    #[clap(alias = "err")]
    #[clap(alias = "error")]
    #[clap(alias = "get-err")]
    #[clap(alias = "get-err-dmp")]
    #[clap(alias = "get-err-dump")]
    #[clap(alias = "get-error-dmp")]
    #[clap(alias = "get-error-dump")]
    GetErrDump(GetErrDump),
    /// Lets the specified device write bytes to the i2c channel and then
    /// transmit the result back to this client
    I2cWriteRead(I2cWriteRead),
    /// Lets the specified device read values from the specified OneWire sensor
    OnewireRead(OnewireRead),
    /// Lets the specified device discover all connected OneWire sensors
    OnewireDiscover,
    /// Lets the specified device read values from the specified custom bus
    CustomRead(CustomRead),
    /// Reconfigure the device's ip, subnet and gateway addresses
    SetNetworkIpSubnetGateway(SetNetworkIpSubnetGateway),
    /// Reconfigures the deivce's mac address
    SetNetworkMac(SetNetworkMac),
    /// List all the device's properties
    #[clap(alias = "list")]
    #[clap(alias = "props")]
    #[clap(alias = "list-props")]
    ListProperties(ListProperties),
    /// Retrieves the value for of the specified property from the device
    #[clap(alias = "get")]
    #[clap(alias = "prop")]
    #[clap(alias = "get-prop")]
    GetProperty(GetProperty),
}

#[derive(Debug, clap::Args)]
pub struct GetVersion;

#[derive(Debug, clap::Args)]
pub struct GetInfo;

#[derive(Debug, clap::Args)]
pub struct GetNetInfo;

#[derive(Debug, clap::Args)]
pub struct GetErrDump;

#[derive(Debug, clap::Args)]
pub struct I2cWriteRead {
    pub i2c_read_len: u8,
    pub i2c_write_bytes: Vec<u8>,
}

#[derive(Debug, clap::Args)]
pub struct OnewireRead {
    /// OneWire addresses of the sensors to read
    pub sensor_address: Vec<Device>,
}

#[derive(Debug, clap::Args)]
pub struct CustomRead {
    /// The address of the bus to read from
    pub bus_address: u8,
}

#[derive(Debug, clap::Args)]
pub struct SetNetworkIpSubnetGateway {
    /// The new ip address for the device
    pub ip: Ipv4Addr,
    /// The new subnet address for the device
    pub subnet: Ipv4Addr,
    /// The new gateway address for the device
    pub gateway: Ipv4Addr,
}

#[derive(Debug, clap::Args)]
pub struct SetNetworkMac {
    /// The new mac address for the device
    pub mac: Mac,
}

#[derive(Debug, Copy, Clone)]
pub struct Mac([u8; 6]);

impl Mac {
    pub fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl FromStr for Mac {
    type Err = core::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const RADIX_HEX: u32 = 16;
        Ok(Self([
            u8::from_str_radix(s.get(0..2).unwrap_or_default(), RADIX_HEX)?,
            u8::from_str_radix(s.get(3..5).unwrap_or_default(), RADIX_HEX)?,
            u8::from_str_radix(s.get(6..8).unwrap_or_default(), RADIX_HEX)?,
            u8::from_str_radix(s.get(9..11).unwrap_or_default(), RADIX_HEX)?,
            u8::from_str_radix(s.get(12..14).unwrap_or_default(), RADIX_HEX)?,
            u8::from_str_radix(s.get(15..17).unwrap_or_default(), RADIX_HEX)?,
        ]))
    }
}

#[derive(Debug, clap::Args)]
pub struct ListProperties {
    /// Whether to not retrieve a full property report (only property ids)
    #[clap(short, long)]
    pub no_report: bool,
}

#[derive(Debug, clap::Args)]
pub struct GetProperty {
    /// The id of  the property to retrieve
    pub property_id: PropertyId,
}

#[derive(Debug, Clone)]
pub struct PropertyId(Vec<u8>);

impl PropertyId {
    pub fn bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl FromStr for PropertyId {
    type Err = core::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut vec = Vec::with_capacity(s.len() / 3);
        for i in 0..(s.len() + 1) / 3 {
            vec.push(
                u8::from_str_radix(
                    s.get(3 * i..)
                        .unwrap_or_default()
                        .get(..2)
                        .unwrap_or_default(),
                    16,
                )
                .unwrap(),
            );
        }
        Ok(PropertyId(vec))
    }
}
