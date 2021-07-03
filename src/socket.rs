use core::fmt;
use std::{fmt::{Display}, net::{IpAddr, Ipv4Addr}, u16, u32};

use anyhow::{Context, Result};
use pnet::{packet::{Packet, ip::{IpNextHeaderProtocols::{self}},util}, transport::{self, TransportChannelType, TransportProtocol, TransportSender}};

use crate::{packet::TCPPacket, tcp};

const SOCKET_BUFFER_SIZE: usize = 4380;


// connection identifier for tcp
#[derive(Debug,Hash,Eq,PartialEq,Clone,Copy)]
pub struct SockID(pub Ipv4Addr,pub Ipv4Addr,pub u16,pub u16);

pub struct Socket {
    pub local_addr: Ipv4Addr,
    pub remote_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_port: u16,
    pub send_param: SendParam,
    pub recv_param: RecvParam,
    pub status: TcpStatus,
    pub sender: TransportSender,
}

#[derive(Debug,Clone)]
pub struct SendParam {
    pub unacked_seq: u32, // head of seq which is unacked 
    pub next: u32,  
    pub window: u16, // window size
    pub initial_seq: u32, 
}

#[derive(Debug,Clone)]
pub struct RecvParam {
    pub next: u32, // next recevice seq
    pub window: u16, // receive window
    pub initial_seq: u32, // initial receive seq
    pub tail: u32 // tails of seq
}

#[derive(PartialEq,Eq,Debug,Clone)]
pub enum TcpStatus {
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    LastAck,
}

impl Display for TcpStatus {
    fn fmt(&self,f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Self::Listen => write!(f,"LISTEN"),
            &Self::SynSent => write!(f,"SYNSENT"),
            &Self::SynRcvd => write !(f,"SYNRCVD"),
            &Self::Established => write!(f, "ESTABLISHED"),
            &Self::FinWait1 => write!(f,"FINWAIT1"),
            &Self::FinWait2 => write!(f,"FINWAIT2"),
            &Self::TimeWait => write!(f,"TIMEWAIT"),
            &Self::CloseWait => write!(f,"CLOSEWAIT"),
            &Self::LastAck => write!(f,"LASTACK"),
        }
    }
}

impl Socket {

    pub fn new(
        local_addr: Ipv4Addr,
        remote_addr: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
        status: TcpStatus
    ) -> Result<Self>
    {
        let (sender,_) = transport::transport_channel(
            65535, 
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)))?;
            Ok(Self{
                local_addr,
                remote_addr,
                local_port,
                remote_port,
                send_param: SendParam{
                    unacked_seq: 0,
                    initial_seq: 0,
                    next: 0,
                    window: SOCKET_BUFFER_SIZE as u16,
                },
                recv_param: RecvParam{
                    initial_seq: 0,
                    next: 0,
                    window: SOCKET_BUFFER_SIZE as u16,
                    tail: 0,
                },
                status,
                sender
            })
    }

    pub fn send_tcp_packet(
        &mut self,
        seq: u32,
        ack: u32,
        flag: u8,
        payload: &[u8]
    ) -> Result<usize> {
        let mut tcp_packet = TCPPacket::new(payload.len());
        tcp_packet.set_src(self.local_port);
        tcp_packet.set_dest(self.remote_port);
        tcp_packet.set_seq(seq);
        tcp_packet.set_ack(ack);
        // ?
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flag(flag);
        tcp_packet.set_window_size(self.recv_param.window);
        tcp_packet.set_payload(payload);
        tcp_packet.set_checksum(util::ipv4_checksum(
            &tcp_packet.packet(),
            8,
            &[],
            &self.local_addr,
            &self.remote_addr,
            IpNextHeaderProtocols::Tcp,
        ));

        let sent_size = self.sender.send_to(tcp_packet.clone(), IpAddr::V4(self.remote_addr))
        .context(format!("failed to send: \n{:?}", tcp_packet))?;
        dbg!("sent",&tcp_packet);
        Ok(sent_size)
    }

    pub fn get_sock_id(&self) -> SockID {
        SockID(
            self.local_addr,
            self.remote_addr,
            self.local_port,
            self.remote_port,
        )
    }

}