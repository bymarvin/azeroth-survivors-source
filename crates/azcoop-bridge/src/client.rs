//! The game process as the bridge sees it (the Python's `client`) and the hooks it reacts to.

use crate::regs::Regs;
use azcoop_logic::{Detail, Event};

pub type Result<T> = std::result::Result<T, String>;

macro_rules! hooks {
    ($($variant:ident $name:literal),* $(,)?) => {
        /// The reviewed hooks, by the names of `native_probe.py`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Hook { $($variant),* }

        impl Hook {
            pub const ALL: &'static [Hook] = &[$(Hook::$variant),*];
            pub fn name(self) -> &'static str {
                match self { $(Hook::$variant => $name),* }
            }
            pub fn from_name(name: &str) -> Option<Hook> {
                match name { $($name => Some(Hook::$variant),)* _ => None }
            }
        }
    };
}

hooks! {
    Tick "TICK", Serialize "SERIALIZE", Write "WRITE", Pause "PAUSE", Resume "RESUME", Start "START", AwardXp "AWARD_XP",
    Choose "CHOOSE", Move "MOVE", Damage "DAMAGE", Hurt "HURT", Spawn "SPAWN", SpawnBoss "SPAWN_BOSS", FindSpawn "FIND_SPAWN",
    SpawnLoot "SPAWN_LOOT", RemoveLoot "REMOVE_LOOT", OfferChoices "OFFER_CHOICES", ApplyEffect "APPLY_EFFECT",
    DefeatUi "DEFEAT_UI", UiCommand "UI_COMMAND", EnemyAoe "ENEMY_AOE", GroundAoe "GROUND_AOE", EnemyTarget "ENEMY_TARGET",
    HudDeliver "HUD_DELIVER", ApplyDot "APPLY_DOT", MapSelect "MAP_SELECT", BossDeath "BOSS_DEATH",
    MenuLogin "MENU_LOGIN",
}

/// `client.call_before(context, rva, argument, second, **kwargs)`: one native call to run for this player.
#[derive(Debug, Clone, PartialEq)]
pub struct CallSpec {
    /// `None`: the call goes through generated entry code (`entry_code=`).
    pub hook: Option<Hook>,
    pub argument: u64,
    pub second: u64,
    pub details: Vec<(&'static str, Detail)>,
}

impl CallSpec {
    pub fn new(hook: Hook, argument: u64, second: u64) -> CallSpec {
        CallSpec { hook: Some(hook), argument, second, details: Vec::new() }
    }
    pub fn with(mut self, key: &'static str, value: Detail) -> CallSpec {
        self.details.push((key, value));
        self
    }
}

pub trait Client {
    fn number(&self) -> u32;
    fn base(&self) -> u64;
    /// `client.server`
    fn server(&self) -> u64;
    fn set_server(&mut self, server: u64);
    fn memory(&mut self, address: u64, len: usize) -> Result<Vec<u8>>;
    fn put(&mut self, address: u64, data: &[u8]) -> Result<()>;
    /// A code patch at an absolute address.
    fn patch(&mut self, address: u64, data: &[u8]) -> Result<()>;
    /// `checked(allocate(handle, None, size, ...))`: a readable and writable block in the game process.
    fn allocate(&mut self, size: usize) -> Result<u64>;
    /// `client.executable_buffer(code, near=...)`; `near` is an absolute address the buffer must be in rel32 reach of.
    fn executable_buffer(&mut self, code: &[u8], near: Option<u64>) -> Result<u64>;
    /// The build's own, unpatched code (what the Python reads from the executable on disk).
    fn image(&self) -> std::rc::Rc<dyn azcoop_patch::Image>;
    /// The game's log says the loading screen of this player cleared.
    fn loading_cleared(&mut self, _number: u32) -> bool {
        false
    }
    /// `client.saved_context is not None`: the game is inside a call this bridge injected.
    fn saved_context(&self) -> bool;
    /// `client.call_is_request`
    fn call_is_request(&self) -> bool;
    /// `client.call_return`: the address an injected call returns to.
    fn call_return(&self) -> u64;
    fn disable_hook(&mut self, hook: Hook);
    /// Runs the native call now (the caller then retries or continues).
    fn call_before(&mut self, regs: &mut Regs, call: CallSpec) -> Result<()>;
    /// `bridge.record(event=...)`: events and client actions share one ordered log.
    fn record(&mut self, event: Event);
}
