//! The TICK hook: a one-shot installation event. The first time the game's update runs for a
//! player it hands over the server object; the bridge then installs its code patches (dispatch
//! guards, shared-world gates, spawn balance, pickup counters) while every game thread is held.

use crate::bridge::Bridge;
use crate::client::{Client, Result};
use crate::process::ClientProcess;
use crate::regs::{self, Regs};
use azcoop_logic::Event;
use azcoop_patch::guards::dispatch_guard_code;
use azcoop_patch::install;
use azcoop_patch::Ctx;

impl Bridge {
    pub(crate) fn tick(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32) -> Result<()> {
        if !self.ticked.insert(number) {
            return Ok(()); // The Python removes the breakpoint after the first hit.
        }
        let base = client.base();
        let image = client.image();
        let ctx = Ctx { variant: self.build.variant, profile: &self.build.profile, image: &*image };
        if !self.menu_players.contains(&number) {
            // Base handler: not for a player whose server went back to the native character selection.
            let server = regs.q(regs::RCX);
            client.set_server(server);
            client.record(Event::new("native_server").num("player", number as f64));
            if !self.dispatch_guards_installed.contains(&number) && !self.skip_patches.contains("guards") {
                Bridge::install_dispatch_guards(client, &ctx, base)?;
                self.dispatch_guards_installed.insert(number);
            }
            let guests = self.room.guests.len();
            if self.shared_world && number == 1 && !self.skip_patches.contains("host_world") {
                let mut process = ClientProcess { client };
                let gate = install::install_host_world(&ctx, &mut process, server, guests)?;
                self.world_enable = gate.world_enable;
                self.guest_target = gate.guest_target;
                self.pursuit_guard = gate.pursuit_guard;
            }
            if self.shared_world && number != 1 && !self.skip_patches.contains("guest_gate") {
                // Keep the native status/buff update tail, skipping independent world simulation.
                install::install_guest_gate(&ctx, &mut ClientProcess { client })?;
                client.record(Event::new("guest_simulation_paused").num("player", number as f64));
            }
        }
        // NativeCombatBridge, after the base handler.
        if number == 1 && self.skip_patches.contains("spawn_balance") {
            client.record(Event::new("patches_skipped").text("which", "spawn_balance"));
        } else if number == 1 {
            let spawn = install::install_spawn_balance(&ctx, &mut ClientProcess { client })?;
            self.spawn_clone = spawn.spawn_clone;
            self.spawn_option = spawn.spawn_option;
            self.spawn_scale = spawn.spawn_scale;
            self.party_xp_buffer = spawn.party_xp_buffer;
            self.economy.gold_counter = spawn.gold_counter;
            #[cfg(feature = "test-hooks")]
            if let Some(stress) = self.stress.clone() {
                stress.install_damage(client)?;
            }
        } else if !self.skip_patches.contains("guest_tick") {
            install::install_guest_tick(&ctx, &mut ClientProcess { client })?;
        }
        Ok(())
    }

    /// `install_dispatch_guards(client)`: only hash-bound contracts admitted by the native profile.
    fn install_dispatch_guards(client: &mut dyn Client, ctx: &Ctx, base: u64) -> Result<()> {
        let number = client.number();
        let mut installed = false;
        for contract in &ctx.profile.dispatch_guards {
            if !contract.mandatory_runtime_guard {
                return Err("Native dispatch contract lacks mandatory guard".into());
            }
            let site = base + contract.rva;
            if client.memory(site, contract.expected.len())? != contract.expected {
                return Err("Native dispatch bytes changed before guard installation".into());
            }
            let code = dispatch_guard_code(ctx, base, contract)?;
            let near = contract.expected.len() < 12;
            let entry = client.executable_buffer(&code, if near { Some(site) } else { None })?;
            let guard = azcoop_patch::guards::GuardInstall {
                kind: contract.kind.clone(),
                rva: contract.rva,
                expected: contract.expected.clone(),
                code,
                near_site: near,
            };
            client.patch(site, &guard.replacement(base, entry)?)?;
            installed = true;
        }
        if installed {
            client.record(Event::new("native_dispatch_guards").num("player", number as f64));
        }
        Ok(())
    }
}
