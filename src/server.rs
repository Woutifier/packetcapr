extern crate pcap;
extern crate hyper;
extern crate rustc_serialize;
use pcap::{Device, Capture};
use std::sync::mpsc::{channel, Sender, Receiver};
use pingnet::PingPacket;
use std::thread;
use hyper::Server;
use hyper::server::{Handler, Request, Response, Fresh};
use std::collections::VecDeque;
use rustc_serialize::json;
use std::net::{SocketAddrV4, TcpStream, UdpSocket, TcpListener, Ipv4Addr};
use Runnable;
use std::str::FromStr;

pub struct CaptureServer {
    address: SocketAddrV4,
}

impl Runnable for CaptureServer {
    fn start(&mut self) {
        let result = Server::http(self.address).unwrap();
        result.handle(self);
    }

    fn exit(&mut self) {

    }
}

impl Handler for CaptureServer {
    fn handle(&self, mut req: Request, mut resp: Response) {
        
    }
}

impl CaptureServer {
    pub fn new(ip: String, port: u16) -> CaptureServer {
        CaptureServer{address: SocketAddrV4::new(Ipv4Addr::from_str(&ip).unwrap(), port)}
    }
}