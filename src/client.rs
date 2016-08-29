extern crate pcap;
extern crate hyper;
extern crate rustc_serialize;
use pcap::{Device, Capture};
use std::sync::mpsc::{channel, Sender, Receiver};
use packet::{PingPacket, PacketContainer};
use std::thread;
use hyper::Client;
use std::collections::VecDeque;
use rustc_serialize::{json, Encodable};
use Runnable;
use std::time::Duration;

pub struct CaptureClient {
    post_url: String,
    buffer_size: u32,
    bpf_filter: String,
    identifier: String,
    timer: Option<u64>,
    sender: Option<Sender<Message>>,
    capture_thread: Option<thread::JoinHandle<()>>,
    transmit_thread: Option<thread::JoinHandle<()>>,
}

enum Message {
    Poison,
    TimerTick,
    Data(PingPacket),
}

impl Runnable for CaptureClient {
    fn exit(&mut self) {
        self.sender
            .clone()
            .unwrap()
            .send(Message::Poison)
            .expect("Could not send poison pill to transmit thread");
        let transmit_thread = self.transmit_thread.take().unwrap();
        transmit_thread.join().expect("Could not exit gracefully");
    }
    fn start(&mut self) {
        let (tx, rx) = channel();
        self.sender = Some(tx.clone());
        self.capture_thread = Some(Self::start_capture(tx.clone(), self.prepare_capture()));
        self.transmit_thread = Some(Self::start_transmit(rx,
                                                         self.post_url.clone(),
                                                         self.buffer_size as usize,
                                                         self.identifier.clone()));
        if self.timer.is_some() {
            let timer_tx = tx.clone();
            let timer_secs = self.timer.unwrap();
            thread::spawn(move || {
                let duration = Duration::from_secs(timer_secs);
                loop {
                    ::std::thread::sleep(duration);
                    timer_tx.send(Message::TimerTick)
                            .expect("Could not send TimerTick to transmit thread");
                }
            });
        }
    }
}

impl CaptureClient {
    pub fn new(post_url: String,
               buffer_size: u32,
               identifier: String,
               timer: Option<u64>,
               bpf_addon: Option<String>)
               -> CaptureClient {
        CaptureClient {
            post_url: post_url,
            buffer_size: buffer_size,
            identifier: identifier,
            timer: timer,
            bpf_filter: CaptureClient::compose_bpf(vec![Some("icmp[icmptype] == icmp-echoreply".to_string()), bpf_addon]),
            sender: None,
            capture_thread: None,
            transmit_thread: None,
        }
    }

    fn compose_bpf(parts: Vec<Option<String>>) -> String {
        let res1 = parts.iter().filter(|x| x.is_some());
        let mut build = "".to_string();
        for r in res1 {
            if build.len() > 0 {
                build = build + " and ";
            }
            build = build + &(r.clone().unwrap());
        }
        build
    }

    fn start_capture<'a>(tx: Sender<Message>,
                         mut cap: Capture<pcap::Active>)
                         -> thread::JoinHandle<()> {
        let t_capture = thread::spawn(move || {
            debug!("[t_capture] Capture thread started");
            while let Ok(packet) = cap.next() {
                debug!("[t_capture] Packet received");
                let pp = PingPacket::from(packet);
                tx.send(Message::Data(pp)).unwrap();
            }
        });
        t_capture
    }

    fn start_transmit(rx: Receiver<Message>,
                      post_url: String,
                      buffer_size: usize,
                      identifier: String)
                      -> thread::JoinHandle<()> {
        let t_transmit = thread::spawn(move || {
            debug!("[t_transmit] Transmit thread started");
            let mut buf = VecDeque::new();
            loop {
                debug!("[t_capture] Transmitting data");
                let data = rx.recv().unwrap();

                match data {
                    Message::Data(data) => {
                        buf.push_back(data);

                        if buf.len() >= buffer_size {
                            let result = Self::http_send_packets(&mut buf, &post_url, &identifier);
                            if result.is_err() {
                                println!("Failed to transmit data. (Retry will occur)");
                            }
                        }
                    }
                    Message::Poison => {
                        let result = Self::http_send_packets(&mut buf, &post_url, &identifier);
                        if result.is_err() {
                            println!("Failed to transmit final batch of data");
                        }
                        break;
                    }
                    Message::TimerTick => {
                        if buf.len() > 0 {
                            let result = Self::http_send_packets(&mut buf, &post_url, &identifier);
                            if result.is_err() {
                                println!("Failed to transmit data. (Retry will occur)");
                            }
                        }
                    }
                }
            }
        });
        t_transmit
    }

    fn http_send_packets<T: Encodable>(buffer: &mut VecDeque<T>,
                                       post_url: &str,
                                       identifier: &str)
                                       -> Result<hyper::client::Response, hyper::Error> {
        // Initialize Hyper client
        let client = Client::new();

        // Take data from the queue
        let collected_packets = buffer.drain(..).collect::<Vec<T>>();

        // Serialize
        let ppc = PacketContainer {
            host_identifier: identifier.to_string(),
            data: collected_packets,
        };
        let encoded_packets = json::encode(&ppc).unwrap();

        // Post
        let result = client.post(post_url)
                           .body(&encoded_packets)
                           .send();

        // In case of an error push data back on to the queue
        if result.is_err() {
            for item in ppc.data {
                buffer.push_back(item);
            }
        }
        result
    }

    fn prepare_capture(&self) -> Capture<pcap::Active> {
        let main_device = Device::lookup().unwrap();
        let mut cap: Capture<pcap::Active> = Capture::from_device(main_device)
                                                 .unwrap()
                                                 .promisc(true)
                                                 .snaplen(5000)
                                                 .open()
                                                 .unwrap();
        cap.filter(&self.bpf_filter).unwrap();
        cap
    }
}

#[cfg(test)]
mod tests {
    use super::CaptureClient;

    #[test]
    fn test_compose_bpf1() {
        let result = CaptureClient::compose_bpf(vec![Some("test1".to_string()), Some("test2".to_string())]);
        assert_eq!(result, "test1 and test2");
    }

    #[test]
    fn test_compose_bpf2() {
        let result = CaptureClient::compose_bpf(vec![Some("icmp[icmptype] == icmp-echoreply".to_string())]);
        assert_eq!(result, "icmp[icmptype] == icmp-echoreply");
    }
}
