use std::net::Ipv4Addr;
use std::env;

use anyhow::Result;
use tcp::TCP;


mod packet;
mod tcp;
mod socket;
mod tcpflags;

fn echo_client(remote_addr: Ipv4Addr,remote_port: u16) -> Result<()>{
    let tcp = TCP::new();
    let _ = tcp.connect(remote_addr, remote_port)?;
    Ok(())
}

fn main() -> Result<()>{
    println!("{:?}",1 << 3);

    let args: Vec<String> = env::args().collect();
    let addr: Ipv4Addr = args[1].parse()?;
    let port: u16 = args[2].parse()?;

    println!("start");

    let result = echo_client(addr, port);
    if let Err(e) = result {
        println!("{:?}",e);
    }

    println!("Hello, world!");
    Ok(())
}
