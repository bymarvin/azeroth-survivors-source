"""Observe native menu command tags in an isolated, windowed profile."""
import json
from native_probe import ROOT, TICK, SERIALIZE, UI_COMMAND, q, run


if __name__ == '__main__':
    with (ROOT / 'analysis/updated-menu-commands.jsonl').open('w') as output:
        def capture(client, rva, context):
            if rva == TICK:
                client.server = q(context, 128)
            elif rva == SERIALIZE:
                client.disable_hooks.add(SERIALIZE)
            elif rva == UI_COMMAND:
                data = client.memory(q(context, 136), 32)
                output.write(json.dumps(dict(command=int.from_bytes(data[:4], 'little'), fields=data.hex())) + '\n')
                output.flush()
        capture.autostart = False
        capture.extra_hooks = (UI_COMMAND,)
        run(240, 1, capture)
