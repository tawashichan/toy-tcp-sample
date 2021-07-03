use std::{collections::{HashMap}, net::{IpAddr, Ipv4Addr}, ops::Range, process::Command, str::from_utf8, sync::{Arc, Condvar}, sync::Mutex, sync::RwLock};

use anyhow::{Context, Result};
use pnet::{packet::{Packet, ip::IpNextHeaderProtocols, tcp::TcpPacket}, transport::{TransportChannelType, ipv4_packet_iter, transport_channel}};
use rand::{Rng, prelude::ThreadRng};

use crate::{packet::TCPPacket, socket::{SockID, Socket, TcpStatus}, tcp, tcpflags};

const UNDETERMINED_IP_ADDR: std::net::Ipv4Addr = Ipv4Addr::new(0,0,0,0);
const UNDETERMINED_PORT: u16 = 0;
const PORT_RANGE: Range<u16> = 40000..60000;


pub struct TCP {
    // multiple threads share sockets so mutex is needed
    sockets: RwLock<HashMap<SockID,Socket>>,
    event_condvar: (Mutex<Option<TCPEvent>>,Condvar)
}

impl TCP {
    pub fn new() -> Arc<Self> {
        let sockets = RwLock::new(HashMap::new());
        let tcp = Arc::new(Self{
            sockets,
            event_condvar: (Mutex::new(None),Condvar::new())
        });
        let cloned_tcp = tcp.clone();
        std::thread::spawn(move || {
            cloned_tcp.receive_handler().unwrap();
        });
        tcp
    }

    fn receive_handler(&self) -> Result<()> {
        dbg!("begin receive thread");
        let (_, mut receiver) = transport_channel(65535, TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)).unwrap();
        let mut packet_iter = ipv4_packet_iter(&mut receiver);

        loop {
            dbg!("waiting packet");
            let (packet,remote_addr) = match packet_iter.next() {
                Ok((p,r)) => (p,r),
                Err(_) => continue
            };
            let local_addr = packet.get_destination();
            let tcp_packet = match TcpPacket::new(packet.payload()) {
                Some(p) => p,
                None => {
                    continue
                }
            };

            // from pnet tcp packet to our tcp packet 
            let packet = TCPPacket::from(tcp_packet);
            dbg!("incoming packet",&packet);
            dbg!("incoming packet seq",&packet.get_seq());
            let remote_addr = match remote_addr {
                IpAddr::V4(addr) => addr,
                _ => {
                    continue;
                }
            };

            let mut table = self.sockets.write().unwrap();
            let socket = match table.get_mut(&SockID(
                local_addr,
                remote_addr,
                packet.get_dest(),
                packet.get_src(),
            )) {
                Some(socket) => socket, // already connected
                None => match table.get_mut(&SockID(
                    local_addr,
                    UNDETERMINED_IP_ADDR,
                    packet.get_dest(),
                    UNDETERMINED_PORT
                )) {
                    Some(socket) => socket, // listening socket
                    None => continue // ignore when no socket found
                }
            };
            if !packet.is_correct_checksum(local_addr, remote_addr) {
                dbg!("invalid checksum");
                continue;
            };
            let sock_id = socket.get_sock_id();
            if let Err(error) = match socket.status {
                crate::socket::TcpStatus::SynSent => self.synsent_handler(socket,&packet),
                _ => {
                    dbg!("not implemented state");
                    Ok(())
                }
            } {
                dbg!(error);
            }
        }
    }

    // handle packets which reached SYNSENT state sockets 
    fn synsent_handler(&self,socket: &mut Socket,packet: &TCPPacket) -> Result<()> {
        dbg!("synsent handler");
        // todo make meaning of this process clear
        if (packet.get_flag() & tcpflags::ACK) > 0 
            && socket.send_param.unacked_seq <= packet.get_ack() 
            && packet.get_ack() <= socket.send_param.next
            && packet.get_flag() & tcpflags::SYN > 0 {
                socket.recv_param.next = packet.get_seq() + 1;
                socket.recv_param.initial_seq = packet.get_seq();
                socket.send_param.unacked_seq = packet.get_ack();
                socket.send_param.window = packet.get_window_size();
               
                if socket.send_param.unacked_seq > socket.send_param.initial_seq {
                     // established case of active open
                    socket.status = TcpStatus::Established;
                    socket.send_tcp_packet(
                        socket.send_param.next,
                        socket.recv_param.next,
                        tcpflags::ACK,
                        &[]
                    )?;
                    dbg!("status: synsent ->",&socket.status);
                    self.publish_event(socket.get_sock_id(), TCPEventKind::ConnectionCompleted);
                } else {
                    // passive open
                    socket.status = TcpStatus::SynRcvd;
                    socket.send_tcp_packet(
                        socket.send_param.next,
                        socket.recv_param.next,
                        tcpflags::ACK,
                        &[]
                    )?;
                    dbg!("status: synsent ->",&socket.status);
                }
        } else {
            dbg!("invalid state");
        }

        Ok(())
    }

    fn select_unused_port(&self,rng: &mut ThreadRng) -> Result<u16> {
        for _ in 0..(PORT_RANGE.end - PORT_RANGE.start) {
            let local_port = rng.gen_range(PORT_RANGE);
            let table = self.sockets.read().unwrap();
            if table.keys().all(|k| local_port != k.2) {
                return Ok(local_port)
            }
        }
        anyhow::bail!("no available port found")
    }

    pub fn connect(&self,addr: Ipv4Addr,port: u16) -> Result<SockID> {
        let mut rng = rand::thread_rng();
        println!("opening socket...");
        let mut socket = Socket::new( 
            get_source_addr_to(addr)?,
            addr,
            self.select_unused_port(&mut rng)?,
            port,
            crate::socket::TcpStatus::SynSent
        )?;
        socket.send_param.initial_seq = rng.gen_range(1..1 << 31);

        dbg!("initial seq",socket.send_param.initial_seq);
      
        socket.send_tcp_packet(
            socket.send_param.initial_seq,
             0,
             tcpflags::SYN, 
             &[]
        )?;

        println!("syn send");
        socket.send_param.unacked_seq = socket.send_param.initial_seq;
        socket.send_param.next = socket.send_param.initial_seq + 1;
        let mut table = self.sockets.write().unwrap();
        let sock_id = socket.get_sock_id();    
        table.insert(sock_id, socket);
        // release lock
        drop(table);
        dbg!("wait connection complete");
        self.wait_event(sock_id,TCPEventKind::ConnectionCompleted);
        dbg!("connection completed");
        Ok(sock_id)
    }
}

fn get_source_addr_to(addr: Ipv4Addr) -> Result<Ipv4Addr> {
    //Ok("10.0.0.1".parse().unwrap())
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ip route get {} | grep src",addr))
        .output()?;
    let mut output = from_utf8(&output.stdout)?
        .trim()
        .split_ascii_whitespace();
    while let Some(s) = output.next() {
        if s == "src" {
            break
        }
    }
    let ip = output.next().context("failed to get src ip")?;
    dbg!("source addr",ip);
    ip.parse().context("failed to parse source ip")  
}

#[derive(Debug,Clone,PartialEq)]
struct TCPEvent {
    sock_id: SockID,
    kind: TCPEventKind
}

#[derive(Debug,Clone,PartialEq)]
pub enum TCPEventKind {
    ConnectionCompleted,
    Acked,
    DataArrived,
    ConnectionClosed,
}

impl TCPEvent {
    fn new(sock_id: SockID,kind: TCPEventKind) -> Self {
        TCPEvent{
            sock_id,
            kind
        }
    }
}

impl TCP {
    
    fn wait_event(&self,sock_id: SockID,kind: TCPEventKind) {
        let (lock,cvar) = &self.event_condvar;
        let mut event  = lock.lock().unwrap();
        loop {
            if let Some(ref e) = *event  {
                if e.sock_id == sock_id && e.kind == kind {
                    break;
                }
            }
            event = cvar.wait(event).unwrap();
        }
        dbg!(&event);
        *event = None;
    }

    fn publish_event(&self,sock_id: SockID,kind: TCPEventKind) {
        let (lock,cvar) = &self.event_condvar;
        let mut e = lock.lock().unwrap();
        *e = Some(TCPEvent::new(sock_id, kind));
        cvar.notify_all();
    }
}