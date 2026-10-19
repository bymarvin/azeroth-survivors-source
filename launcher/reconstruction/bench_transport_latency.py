"""Loopback latency of the co-op transport (coop_transport.Channel over TLS), for before/after comparisons.

    python bench_transport_latency.py [--echoes 10000] [--load-seconds 30]

1. Echo: the host sends a small message, the guest thread answers as soon as it arrives (blocking queue get,
   no polling of its own). Reports round-trip percentiles over --echoes messages.
2. Ping under load: the host streams 30 KB world-like messages at 25 Hz to the guest while both sides run
   their normal ping probes; reports the guest's and host's latency_ms() samples (what the game shows).
Boot-log output; one progress line per second at most.
"""
import argparse
import queue
import socket
import statistics
import tempfile
import threading
import time

from coop_transport import accept, connect, create_pairing


def log(label, text):
    print(f'[{label:^6}] {text}', flush=True)


def pair(folder):
    invite = create_pairing(folder)
    listener = socket.create_server(('127.0.0.1', 0))
    result = []
    thread = threading.Thread(target=lambda: result.append(accept(listener, folder, invite, 'bench')))
    thread.start()
    guest = connect('127.0.0.1', listener.getsockname()[1], invite, 'bench')
    thread.join(10)
    listener.close()
    return result[0], guest


def percentiles(values):
    values = sorted(values)
    q = lambda p: values[min(len(values) - 1, int(p * len(values)))] * 1000
    return f'p50={q(.5):.2f} ms p90={q(.9):.2f} ms p99={q(.99):.2f} ms max={values[-1] * 1000:.1f} ms mean={statistics.fmean(values) * 1000:.2f} ms'


def echo(host, guest, count):
    stop = threading.Event()

    def answer():
        while not stop.is_set():
            try:
                message = guest.incoming.get(timeout=.5)
            except queue.Empty:
                continue
            if message.get('kind') == 'echo':
                guest.send(dict(kind='echo_reply', n=message['n']))

    worker = threading.Thread(target=answer, daemon=True)
    worker.start()
    samples, last = [], time.monotonic()
    log(' .... ', f'echo {count} round trips')
    for n in range(count):
        started = time.perf_counter()
        host.send(dict(kind='echo', n=n))
        while True:
            reply = host.incoming.get(timeout=5)
            if reply.get('kind') == 'echo_reply' and reply['n'] == n:
                break
        samples.append(time.perf_counter() - started)
        if time.monotonic() - last >= 1:
            log(f'{100 * (n + 1) // count:3} %', f'{n + 1}/{count} echoes, running {percentiles(samples)}')
            last = time.monotonic()
    stop.set()
    worker.join(2)
    log('  OK  ', f'echo n={count} {percentiles(samples)}')
    return samples


def under_load(host, guest, seconds):
    log(' .... ', f'ping under load {seconds} s (30 KB at 25 Hz host->guest)')
    blob = 'w' * 30000
    host_samples, guest_samples = [], []
    end, last, tick = time.monotonic() + seconds, time.monotonic(), time.monotonic()
    while time.monotonic() < end:
        host.send(dict(kind='world', data=blob))
        guest.send(dict(kind='input', n=1))
        guest.drain()
        host.drain()
        for channel, bucket in ((host, host_samples), (guest, guest_samples)):
            value = channel.latency_ms()
            if value is not None and (not bucket or bucket[-1][0] != channel.latency_sample[1]):
                bucket.append((channel.latency_sample[1], value))
        tick += .04
        time.sleep(max(0, tick - time.monotonic()))
        if time.monotonic() - last >= 1:
            log(' INFO ', f'host samples {len(host_samples)}, guest samples {len(guest_samples)}')
            last = time.monotonic()
    for name, bucket in (('host', host_samples), ('guest', guest_samples)):
        values = sorted(v for _, v in bucket)
        if values:
            log('  OK  ', f'latency_ms {name}: n={len(values)} p50={values[len(values) // 2]} max={values[-1]}')
        else:
            log(' WARN ', f'latency_ms {name}: no samples')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--echoes', type=int, default=10000)
    parser.add_argument('--load-seconds', type=float, default=30)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as folder:
        host, guest = pair(folder)
        try:
            echo(host, guest, args.echoes)
            if args.load_seconds > 0:
                under_load(host, guest, args.load_seconds)
        finally:
            host.close()
            guest.close()


if __name__ == '__main__':
    main()
