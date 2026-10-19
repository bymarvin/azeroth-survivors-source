//! `azcoop_logic::Io` over a [`Client`]: game fields by legacy offset, server and absolute
//! addresses, and native calls with the argument shapes of the Python's `call_before` sites.

use crate::client::{CallSpec, Client, Hook};
use crate::regs::Regs;
use azcoop_game::readers::GameFields;
use azcoop_logic::results::Results;
use azcoop_logic::{Call, Detail, Event, Io};

type Result<T> = std::result::Result<T, String>;

pub struct GameIo<'a> {
    pub client: &'a mut dyn Client,
    pub regs: &'a mut Regs,
    pub fields: &'a GameFields,
    pub results: &'a mut Results,
    pub number: u32,
    /// The loot vector pointer seen by the last read of `Game+0x5C8` (the records are read behind it).
    loot_pointer: u64,
}

impl<'a> GameIo<'a> {
    pub fn new(client: &'a mut dyn Client, regs: &'a mut Regs, fields: &'a GameFields, results: &'a mut Results) -> GameIo<'a> {
        let number = client.number();
        GameIo { client, regs, fields, results, number, loot_pointer: 0 }
    }

    pub fn game(&self) -> u64 {
        self.client.server() + 0x10
    }

    fn field_address(&self, field: u64) -> Result<u64> {
        Ok(self.game() + self.fields.get(field)?)
    }
}

fn bytes4(v: &[u8]) -> [u8; 4] {
    v[..4].try_into().unwrap()
}

impl Io for GameIo<'_> {
    fn base(&self) -> u64 {
        self.client.base()
    }
    fn read_f32(&mut self, field: u64) -> Result<f32> {
        let a = self.field_address(field)?;
        Ok(f32::from_le_bytes(bytes4(&self.client.memory(a, 4)?)))
    }
    fn read_u8(&mut self, field: u64) -> Result<u8> {
        let a = self.field_address(field)?;
        Ok(self.client.memory(a, 1)?[0])
    }
    fn read_u32x2(&mut self, field: u64) -> Result<[u32; 2]> {
        let a = self.field_address(field)?;
        let v = self.client.memory(a, 8)?;
        Ok([u32::from_le_bytes(v[..4].try_into().unwrap()), u32::from_le_bytes(v[4..8].try_into().unwrap())])
    }
    fn put_f32(&mut self, field: u64, value: f32) {
        if let Ok(a) = self.field_address(field) {
            let _ = self.client.put(a, &value.to_le_bytes());
        }
    }
    fn put_u32x2(&mut self, field: u64, value: [u32; 2]) {
        if let Ok(a) = self.field_address(field) {
            let mut v = value[0].to_le_bytes().to_vec();
            v.extend_from_slice(&value[1].to_le_bytes());
            let _ = self.client.put(a, &v);
        }
    }
    fn put_u8(&mut self, field: u64, value: u8) {
        if let Ok(a) = self.field_address(field) {
            let _ = self.client.put(a, &[value]);
        }
    }
    fn read_bytes(&mut self, field: u64, len: usize) -> Result<Vec<u8>> {
        let a = self.field_address(field)?;
        let v = self.client.memory(a, len)?;
        if field == 0x5C8 && len == 16 {
            self.loot_pointer = u64::from_le_bytes(v[..8].try_into().unwrap());
        }
        Ok(v)
    }
    fn put_bytes(&mut self, field: u64, value: &[u8]) {
        if let Ok(a) = self.field_address(field) {
            let _ = self.client.put(a, value);
        }
    }
    fn read_raw(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let a = self.game() + offset;
        self.client.memory(a, len)
    }
    fn read_loot(&mut self, len: u64) -> Result<Vec<u8>> {
        self.client.memory(self.loot_pointer, len as usize)
    }
    fn read_server(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let a = self.client.server() + offset;
        self.client.memory(a, len)
    }
    fn put_server(&mut self, offset: u64, value: &[u8]) {
        let a = self.client.server() + offset;
        let _ = self.client.put(a, value);
    }
    fn put_abs(&mut self, address: u64, value: &[u8]) {
        let _ = self.client.put(address, value);
    }
    fn read_abs(&mut self, address: u64, len: usize) -> Result<Vec<u8>> {
        self.client.memory(address, len)
    }
    fn code_read(&mut self, rva: u64, len: usize) -> Result<Vec<u8>> {
        let a = self.client.base() + rva;
        self.client.memory(a, len)
    }
    fn code_patch(&mut self, rva: u64, bytes: &[u8]) -> Result<()> {
        let a = self.client.base() + rva;
        self.client.patch(a, bytes)
    }
    fn call(&mut self, call: Call) -> Result<()> {
        let game = self.game();
        let spec = match call {
            Call::DefeatUi => CallSpec::new(Hook::DefeatUi, game, 0),
            Call::Resume => CallSpec::new(Hook::Resume, game, 0),
            Call::Pause => CallSpec::new(Hook::Pause, game, 0),
            Call::PauseUi => CallSpec::new(Hook::Pause, game, 0).with("ui_only", Detail::Num(1.0)),
            Call::ResumeUi => CallSpec::new(Hook::Resume, game, 0).with("ui_only", Detail::Num(1.0)),
            Call::Hurt { attacker, damage, melee } => {
                CallSpec::new(Hook::Hurt, game, attacker).with("damage", Detail::Num(damage)).with("melee", Detail::Num(melee as u8 as f64))
            }
            Call::AwardXp { amount } => CallSpec::new(Hook::AwardXp, game, amount),
            Call::RemoveLoot { index } => CallSpec::new(Hook::RemoveLoot, game, index),
            Call::OfferChoices { kind } => CallSpec::new(Hook::OfferChoices, game, kind),
            Call::Surrender => CallSpec { hook: None, argument: game, second: 0, details: vec![("entry_code", Detail::Text(surrender_entry(self.client.base())))] },
            Call::SpawnMirror { boss, position } => {
                CallSpec::new(if boss.is_none() { Hook::Spawn } else { Hook::SpawnBoss }, game, boss.unwrap_or(0))
                    .with("position", Detail::List(position.to_vec()))
            }
            Call::Damage { enemy, amount } => CallSpec::new(Hook::Damage, game, enemy).with("damage", Detail::Num(amount)),
        };
        self.client.call_before(self.regs, spec)
    }
    fn rearm_result(&mut self, reason: &str) -> Result<()> {
        let mut results = std::mem::take(self.results);
        let number = self.number;
        let outcome = results.rearm_result(self, number, reason);
        *self.results = results;
        outcome
    }
    fn record(&mut self, event: Event) {
        self.client.record(event);
    }
}

/// `b'\x48\xb8' + pack('<Q', base + SURRENDER_ENTRY) + b'\xff\xe0'`, hex.
pub fn surrender_entry(base: u64) -> String {
    let mut code = vec![0x48, 0xB8];
    code.extend_from_slice(&(base + 0x546E540).to_le_bytes());
    code.extend([0xFF, 0xE0]);
    code.iter().map(|b| format!("{b:02x}")).collect()
}
