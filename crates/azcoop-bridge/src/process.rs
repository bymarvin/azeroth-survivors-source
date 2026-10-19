//! A [`Client`] as the installer's [`Process`]: patch sites are relative to the image base.

use crate::client::Client;
use azcoop_logic::{Detail, Event};
use azcoop_patch::install::{Note, Process};

pub struct ClientProcess<'a> {
    pub client: &'a mut dyn Client,
}

impl Process for ClientProcess<'_> {
    fn base(&self) -> u64 {
        self.client.base()
    }
    fn memory(&mut self, rva: u64, len: usize) -> Result<Vec<u8>, String> {
        let address = self.client.base() + rva;
        self.client.memory(address, len)
    }
    fn patch(&mut self, rva: u64, bytes: &[u8]) -> Result<(), String> {
        let address = self.client.base() + rva;
        self.client.patch(address, bytes)
    }
    fn executable_buffer(&mut self, code: &[u8], near: Option<u64>) -> Result<u64, String> {
        let near = near.map(|rva| self.client.base() + rva);
        self.client.executable_buffer(code, near)
    }
    fn allocate(&mut self, size: usize) -> Result<u64, String> {
        self.client.allocate(size)
    }
    fn put(&mut self, address: u64, bytes: &[u8]) -> Result<(), String> {
        self.client.put(address, bytes)
    }
    fn event(&mut self, name: &str, details: &[(&str, Note)]) {
        let mut event = Event::new(name);
        for (key, note) in details {
            event.details.push((key.to_string(), match note {
                Note::Num(x) => Detail::Num(*x),
                Note::List(l) => Detail::List(l.clone()),
            }));
        }
        self.client.record(event);
    }
}
