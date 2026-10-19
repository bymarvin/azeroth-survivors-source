//! Game file patch generator: bsdiff algorithm (Colin Percival) on a divsufsort
//! suffix array. Runs on our side only; players apply the result with the pure
//! Python applier in coop-lab/updater/game_patch.py.
//!
//!   azpatch-gen <old file> <new file> <output prefix>
//!
//! Writes three raw streams that game_patch.py compresses (lzma) and packs:
//!   <prefix>.ctrl   (add_len, extra_len, seek) as little-endian i64 triples
//!   <prefix>.diff   new - old byte-wise (wrapping) for every add run
//!   <prefix>.extra  new bytes without an old counterpart
//! Boot-log lines on stdout.

use std::env;
use std::fs;
use std::io::{BufWriter, Write};
use std::time::Instant;

fn log(tag: &str, text: &str) {
    println!("[{:^6}] {}", tag, text);
    let _ = std::io::stdout().flush();
}

fn match_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

/// Longest match of `new` among the suffixes sa[st..=en] of `old`: (old position, length).
fn search(sa: &[i32], old: &[u8], new: &[u8], mut st: usize, mut en: usize) -> (usize, usize) {
    loop {
        if en - st < 2 {
            let x = match_len(&old[sa[st] as usize..], new);
            let y = match_len(&old[sa[en] as usize..], new);
            return if x > y { (sa[st] as usize, x) } else { (sa[en] as usize, y) };
        }
        let mid = st + (en - st) / 2;
        let suffix = &old[sa[mid] as usize..];
        let n = suffix.len().min(new.len());
        if suffix[..n] < new[..n] {
            st = mid;
        } else {
            en = mid;
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: azpatch-gen <old> <new> <output prefix>");
        std::process::exit(2);
    }
    let started = Instant::now();
    log(" .... ", &format!("read {} and {}", args[1], args[2]));
    let old = fs::read(&args[1]).expect("old file");
    let new = fs::read(&args[2]).expect("new file");
    if old.len() >= i32::MAX as usize || new.len() >= i32::MAX as usize {
        log("FAILED", "files above 2 GiB need a 64-bit suffix array");
        std::process::exit(1);
    }
    log("  OK  ", &format!("read ({:.1} s, old {} B, new {} B)", started.elapsed().as_secs_f64(), old.len(), new.len()));

    let t = Instant::now();
    log(" .... ", "suffix array");
    let sa: Vec<i32> = if old.is_empty() { Vec::new() } else { divsufsort::sort(&old).into_parts().1 };
    log("  OK  ", &format!("suffix array ({:.1} s, {:.1} MB/s)", t.elapsed().as_secs_f64(),
                           old.len() as f64 / 1e6 / t.elapsed().as_secs_f64().max(1e-9)));

    let prefix = &args[3];
    let mut ctrl = BufWriter::new(fs::File::create(format!("{prefix}.ctrl")).expect("ctrl"));
    let mut diff = BufWriter::new(fs::File::create(format!("{prefix}.diff")).expect("diff"));
    let mut extra = BufWriter::new(fs::File::create(format!("{prefix}.extra")).expect("extra"));

    let t = Instant::now();
    log(" .... ", "match scan");
    let (oldsize, newsize) = (old.len() as i64, new.len() as i64);
    let (mut scan, mut len, mut pos) = (0i64, 0i64, 0i64);
    let (mut lastscan, mut lastpos, mut lastoffset) = (0i64, 0i64, 0i64);
    let (mut diff_bytes, mut extra_bytes, mut controls) = (0u64, 0u64, 0u64);
    let mut next_report = Instant::now() + std::time::Duration::from_secs(10);
    while scan < newsize {
        let mut oldscore = 0i64;
        scan += len;
        let mut scsc = scan;
        while scan < newsize {
            if old.is_empty() {
                pos = 0;
                len = 0;
            } else {
                let (p, l) = search(&sa, &old, &new[scan as usize..], 0, sa.len() - 1);
                pos = p as i64;
                len = l as i64;
            }
            while scsc < scan + len {
                if scsc + lastoffset < oldsize && old[(scsc + lastoffset) as usize] == new[scsc as usize] {
                    oldscore += 1;
                }
                scsc += 1;
            }
            if (len == oldscore && len != 0) || len > oldscore + 8 {
                break;
            }
            if scan + lastoffset < oldsize && old[(scan + lastoffset) as usize] == new[scan as usize] {
                oldscore -= 1;
            }
            scan += 1;
        }
        if len != oldscore || scan == newsize {
            let (mut s, mut sf, mut lenf, mut i) = (0i64, 0i64, 0i64, 0i64);
            while lastscan + i < scan && lastpos + i < oldsize {
                if old[(lastpos + i) as usize] == new[(lastscan + i) as usize] {
                    s += 1;
                }
                i += 1;
                if s * 2 - i > sf * 2 - lenf {
                    sf = s;
                    lenf = i;
                }
            }
            let mut lenb = 0i64;
            if scan < newsize {
                let (mut s, mut sb, mut i) = (0i64, 0i64, 1i64);
                while scan >= lastscan + i && pos >= i {
                    if old[(pos - i) as usize] == new[(scan - i) as usize] {
                        s += 1;
                    }
                    if s * 2 - i > sb * 2 - lenb {
                        sb = s;
                        lenb = i;
                    }
                    i += 1;
                }
            }
            if lastscan + lenf > scan - lenb {
                let overlap = (lastscan + lenf) - (scan - lenb);
                let (mut s, mut ss, mut lens) = (0i64, 0i64, 0i64);
                for i in 0..overlap {
                    if new[(lastscan + lenf - overlap + i) as usize] == old[(lastpos + lenf - overlap + i) as usize] {
                        s += 1;
                    }
                    if new[(scan - lenb + i) as usize] == old[(pos - lenb + i) as usize] {
                        s -= 1;
                    }
                    if s > ss {
                        ss = s;
                        lens = i + 1;
                    }
                }
                lenf += lens - overlap;
                lenb -= lens;
            }
            let block: Vec<u8> = (0..lenf)
                .map(|i| new[(lastscan + i) as usize].wrapping_sub(old[(lastpos + i) as usize]))
                .collect();
            diff.write_all(&block).expect("write diff");
            let extra_len = (scan - lenb) - (lastscan + lenf);
            extra.write_all(&new[(lastscan + lenf) as usize..(lastscan + lenf + extra_len) as usize]).expect("write extra");
            let seek = (pos - lenb) - (lastpos + lenf);
            for value in [lenf, extra_len, seek] {
                ctrl.write_all(&value.to_le_bytes()).expect("write ctrl");
            }
            diff_bytes += lenf as u64;
            extra_bytes += extra_len as u64;
            controls += 1;
            lastscan = scan - lenb;
            lastpos = pos - lenb;
            lastoffset = pos - scan;
        }
        if Instant::now() >= next_report {
            next_report = Instant::now() + std::time::Duration::from_secs(10);
            log(&format!("{:3} %", scan * 100 / newsize.max(1)),
                &format!("match scan {}/{} B, {:.1} MB/s", scan, newsize, scan as f64 / 1e6 / t.elapsed().as_secs_f64()));
        }
    }
    for writer in [&mut ctrl, &mut diff, &mut extra] {
        writer.flush().expect("flush");
    }
    log("  OK  ", &format!("match scan ({:.1} s, {} controls, diff {} B, extra {} B; total {:.1} s)",
                           t.elapsed().as_secs_f64(), controls, diff_bytes, extra_bytes, started.elapsed().as_secs_f64()));
}
