"""0.84.3 native raid packets and a bounded native-UI minimap overlay.

Wire icons are zero based. Shared slots never change during a run; SELF is
recipient-local, not the host's identity. No executable or game asset edits.
"""
import struct

from world_packets import SELF

SUPPORTED_HASH = 'dc165e348d0a15062f58d83530619b0f57479028a28507f449c8bcffea0fb306'
# 0.92.0 (47e4ab65): same client strings (RAID_TARGET_UPDATE, SetRaidTarget, CHAT_MSG_ADDON, minimapInsideZoom,
# UI-RaidTargetingIcons, ObjectIcons) and the 0x96 notice path already verified by the revival acceptance.
SUPPORTED_HASHES = frozenset((SUPPORTED_HASH, '47e4ab65c1ad7366e554171a6a28b0272141664010a50795371129b203111bf2',
                              '0315cf387f4f807512ac965763ed81ae58e7f20dd94547a7541ee8eae3135f66',
                              # 0.95.0 (7264d50b): the same six client strings, same counts as 0.93.1.
                              '7264d50b82a1ecc2b5f0fcf2f29669c2acaa8bb87c058e17898a47a12984ff30'))


def native_guid(player, recipient):
    return SELF if player == recipient else 0xFF0100 + player


def validate_assignments(value, members):
    if not isinstance(value, dict) or len(value) > 4:
        raise ValueError('Invalid raid assignments')
    result = {}
    for player, icon in value.items():
        if player not in {str(n) for n in members} or type(icon) is not int or not 0 <= icon < 8:
            raise ValueError('Invalid raid assignment')
        result[int(player)] = icon
    if len(set(result.values())) != len(result):
        raise ValueError('Duplicate raid icons')
    return result


def raid_packet(assignments, recipient, visible):
    return 0x321, b'\x01' + b''.join(
        struct.pack('<BQ', icon, native_guid(player, recipient))
        for player, icon in sorted(assignments.items())
        if player == recipient or player in visible)


def minimap_packet(rows, downed=False):
    """Full replacement snapshot: slot, relative north/west, downed, UTF-8 name.

    The synthetic addon message is injected into this client's native queue;
    it is never accepted as a remote peer command or sent to a game server.
    """
    text = ('ATMARK\t' + str(int(downed)) + '|' + ';'.join(
        f'{n},{dx:.3f},{dy:.3f},{int(dead)},{name.encode("utf-8").hex()}'
        for n, dx, dy, dead, name in rows)).encode('ascii')
    return 0x96, struct.pack('<BIQQI', 1, 0xFFFFFFFF, SELF, SELF, len(text) + 1) + text + b'\0\0'


def reject_remote_marker_packet(opcode, body):
    # Peers may relay ordinary/native addon chat, but cannot drive this local
    # UI control channel (including through the host's third-party fan-out).
    if opcode == 0x96 and body[1:5] == b'\xff' * 4 and b'ATMARK\t' in body:
        raise ValueError('Party marker snapshots are local-only')


def install_minimap(folder):
    """Only the launched client's profile, never its shared game Data directory."""
    addon = folder / 'AddOns' / 'AzerothTogetherMarkers'
    addon.mkdir(parents=True, exist_ok=True)
    (addon / 'AzerothTogetherMarkers.toc').write_text(
        '## Interface: 11200\n## Title: Azeroth Together party markers\nmarkers.lua\n', encoding='utf-8')
    (addon / 'markers.lua').write_text(MINIMAP_LUA, encoding='utf-8')


def append_markers(bridge, recipient, packets):
    """Called after native objects/queued deltas, on the existing debugger thread."""
    import time
    from visibility_bridge import character_name
    active = (not bridge.draining and not bridge.restart_requested
              and not bridge.menu_players and bridge.native_states.get(1, (0,))[0] != 5)
    if getattr(bridge, 'number', 1) == 1 and not active:
        bridge.raid_assignments.clear()
    assignments = bridge.raid_assignments if active else {}
    board = raid_packet(assignments, recipient, bridge.created[recipient])
    if bridge.raid_sent.get(recipient) != board:
        packets.append(board)
        bridge.raid_sent[recipient] = board
        bridge.record(event='raid_markers_written', recipient=recipient,
                      assignments=assignments, body=board[1].hex())
    now = time.monotonic()
    if now - bridge.minimap_sent.get(recipient, 0) < .1:
        return
    bridge.minimap_sent[recipient] = now
    rows = []
    if active and recipient in bridge.ready:
        origin = bridge.pose(recipient)
        for player in bridge.members:
            if player == recipient or player not in bridge.created[recipient]:
                continue
            pose = bridge.pose(player)
            name = (character_name(bridge.name_responses[player]) if player in bridge.name_responses
                    else f'Player {player}')
            rows.append((player, pose.x - origin.x, pose.y - origin.y,
                         bridge.native_states.get(player, (0,))[0] == 4, name))
    packets.append(minimap_packet(rows, active and bridge.native_states.get(recipient, (0,))[0] == 4))


# Embedded so the existing Python source-bound compatibility identity covers
# the Lua payload too. This build has north-up maps, not a rotation CVar.
MINIMAP_LUA = r'''
local receiver = CreateFrame("Frame")
local markers, rows = {}, {}
local received, elapsed = 0, 0
local selfDown = false
local outdoor = {233.333333, 200, 166.666667, 133.333333, 100, 66.666667}
local indoor = {150, 120, 90, 60, 40, 25}
local function solid(frame, width, height, x, y, r, g, b)
    local t = frame:CreateTexture(nil, "OVERLAY")
    t:SetWidth(width); t:SetHeight(height)
    t:SetPoint("CENTER", frame, "CENTER", x, y)
    t:SetTexture(r, g, b)
    return t
end
local function marker(n)
    if markers[n] then return markers[n] end
    local f = CreateFrame("Frame", nil, Minimap)
    f:SetWidth(14); f:SetHeight(16); f:SetFrameLevel(Minimap:GetFrameLevel() + 8)
    f:EnableMouse(true)
    f.dot = f:CreateTexture(nil, "OVERLAY")
    f.dot:SetWidth(11); f.dot:SetHeight(11); f.dot:SetPoint("CENTER", f, "CENTER")
    f.dot:SetTexture("Interface\\Minimap\\ObjectIcons")
    f.dot:SetTexCoord(0, .25, .25, .5)
    f.grave = CreateFrame("Frame", nil, f)
    f.grave:SetAllPoints(f)
    solid(f.grave, 10, 11, 0, 0, .65, .68, .72)
    solid(f.grave, 6, 2, 0, 6, .65, .68, .72)
    solid(f.grave, 14, 3, 0, -6, .4, .43, .47)
    solid(f.grave, 2, 7, 0, 0, .15, .17, .2)
    solid(f.grave, 6, 2, 0, 1, .15, .17, .2)
    f:SetScript("OnEnter", function()
        GameTooltip:SetOwner(this, "ANCHOR_RIGHT")
        GameTooltip:SetText(this.playerName or "Party member")
        GameTooltip:Show()
    end)
    f:SetScript("OnLeave", function() GameTooltip:Hide() end)
    markers[n] = f
    return f
end
receiver:RegisterEvent("CHAT_MSG_ADDON")
receiver:RegisterEvent("PLAYER_LEAVING_WORLD")
receiver:SetScript("OnEvent", function()
    if event == "PLAYER_LEAVING_WORLD" then rows = {}; selfDown = false; return end
    if arg1 ~= "ATMARK" then return end
    rows = {}
    selfDown = string.sub(arg2 or "", 1, 2) == "1|"
    local each = string.gfind or string.gmatch
    for n, dx, dy, dead, name in each(arg2 or "", "(%d),([%-%.%d]+),([%-%.%d]+),([01]),(%x*)") do
        n = tonumber(n); dx = tonumber(dx); dy = tonumber(dy)
        if n and n >= 1 and n <= 4 and dx and dy and string.len(name) <= 192 then
            name = string.gsub(name, "%x%x", function(pair) return string.char(tonumber(pair, 16)) end)
            rows[n] = {dx, dy, dead == "1", name}
        end
    end
    received = GetTime()
end)
receiver:SetScript("OnUpdate", function()
    elapsed = elapsed + arg1
    if elapsed < .1 then return end
    elapsed = 0
    if not Minimap then return end
    if GetTime() - received > 2 then rows = {}; selfDown = false end
    -- Co-op revives this same native avatar; releasing spirit would start an
    -- unrelated single-player ghost/corpse lifecycle.
    if selfDown then StaticPopup_Hide("DEATH") end
    local zoom = Minimap:GetZoom()
    -- Reviewed native SetZoom writes only the active indoor/outdoor CVar
    -- synchronously. Probe then restore in the same Lua callback: no visible
    -- zoom change or changed saved setting. This build has no IsIndoors API.
    local before = GetCVar("minimapInsideZoom")
    Minimap:SetZoom(math.mod(zoom + 1, 6))
    local inside = GetCVar("minimapInsideZoom") ~= before
    Minimap:SetZoom(zoom)
    local radius = (inside and indoor or outdoor)[zoom + 1]
    local size = Minimap:GetWidth()
    for n, f in pairs(markers) do if not rows[n] then f:Hide() end end
    for n, row in pairs(rows) do
        local f = marker(n)
        local x, y = -row[2] * size / (2 * radius), row[1] * size / (2 * radius)
        local distance = math.sqrt(x*x + y*y)
        local limit = size * .5 - 9
        if distance > limit then x = x * limit / distance; y = y * limit / distance end
        f:ClearAllPoints(); f:SetPoint("CENTER", Minimap, "CENTER", x, y)
        f.playerName = row[4]
        if row[3] then f.dot:Hide(); f.grave:Show() else f.grave:Hide(); f.dot:Show() end
        f:Show()
    end
end)
'''
