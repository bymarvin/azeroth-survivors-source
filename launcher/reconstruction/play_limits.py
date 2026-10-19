"""Limits for values that real play reaches (endless mode, many hours, extreme builds).

Decision 17.10.2026 (user): "Ich will das es kein limit gibt die leute sollen so
weit spielen wie sie können". No bound in this module may end a session through
real play:
- accumulating state is cleaned up (out of range, expired, dead, despawned) and
  at most drops its oldest entries (logged), see guest_auras and note_bound;
- single values that grow in endgame (damage, health, rewards, clock) have
  bounds far above anything a run reaches; u32 native counters saturate or are
  applied in parts instead of raising;
- the remaining bounds only reject broken or hostile data (finite, sane sizes)
  and sit at least 10x above real play.
Pure module (no imports): shared by the native bridge, the wire and the tests.
"""
MAX_ENEMY_DAMAGE = 1e12       # One player hit or batch delta on one enemy (f32 native).
MAX_HIT_DAMAGE = 1e12         # One enemy hit on a player (native HURT argument, wire).
MAX_ENEMY_HP = 1e15           # Enemy and player (revival) health.
MAX_DAMAGE_TOTAL = 1e18       # Cumulative damage receipts per enemy.
MAX_CLOCK = 1e9               # Seconds of native game clock (31 years).
MAX_MULTIPLIER = 1e6          # XP/gold/chest multipliers.
MAX_COUNTER = 0xFFFFFFFF      # Native u32 counters: XP, gold, levels, state values.
MAX_ENEMIES = 32768           # Enemies alive at once (native vector, wire snapshot, aura batch).
MAX_LIVE_SUMMONS = 4096       # Live totems/companions/ground spells per player.
MAX_CLASS_ENTRIES = 4096      # Class XP entries of one account (the game has a few dozen classes).
SUMMON_HISTORY = 100000       # Summon identities per guest incl. destroyed ones (oldest destroyed dropped).
MAX_QUEUE = 65536             # Per-batch queues and packet lists (effects, packets, UI, movement).
MAX_NATIVE_OBJECTS = 1000000  # Native loot/projectile/gear vectors, loot objects on the wire.
MAX_WORLD_OBJECTS = 1000000   # Host world objects tracked for forwarding.
MAX_NATIVE_READ = 256 << 20   # One native memory read (10x enemies or loot fit into one read).
MAX_MESSAGE = 32 << 20        # One co-op message (a full snapshot of MAX_ENEMIES enemies fits).
MAX_WORLD_BACKLOG = MAX_MESSAGE // 2  # Host world bytes between two sends (base64 in one message).


def u32_part(pending):
    """The part of a pending u32 reward one native call can apply; the rest follows next batch."""
    return min(pending, MAX_COUNTER)


def copper(gold):
    """Gold shown in the player copper field (u32): saturates instead of overflowing."""
    return min(gold * 10000, MAX_COUNTER)
