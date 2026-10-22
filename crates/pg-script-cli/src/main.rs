//! `qs` — QED Script developer CLI.
//!
//! qs keygen <seed.hex> <pub.rs> <pub.hex>
//! qs sign   --seed <seed.hex> <dir>            (reads app.wasm app.policy [app.proof], writes app.sig)
//! qs verify [--pub <pub.hex>] <dir>
//! qs run    [--pub <pub.hex>] [--method GET|POST] [--path P] [--query Q] [--body S | --body-file F]
//!           [--content-type T] [--principal N] [--repeat N] [--mem-kb N] <dir>
//!
//! Execution inside the seL4 appliance happens in the Script PD; `run` is the host-side reference.
use pg_config::{public_key_from_seed, sign_ed25519};
use pg_script::{execute, Clock, Method, NoClock, Request};
use pg_script_policy::Kv;
use pg_script_verify::{load, signed_message, MSG_MAX, CODE_SIGNING_PUBLIC_KEY};
use std::{env, fs, process::exit, time::Instant};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("bad hex")).collect()
}
fn die(m: &str) -> ! {
    eprintln!("qs: {m}");
    exit(2)
}

struct WallClock(Instant);
impl Clock for WallClock {
    fn elapsed_us(&mut self) -> u64 {
        self.0.elapsed().as_micros() as u64
    }
}

fn main() {
    let a: Vec<String> = env::args().skip(1).collect();
    match a.first().map(|s| s.as_str()) {
        Some("keygen") if a.len() == 4 => {
            let mut seed = [0u8; 32];
            use std::io::Read;
            fs::File::open("/dev/urandom").unwrap().read_exact(&mut seed).unwrap();
            let pubk = public_key_from_seed(&seed);
            fs::write(&a[1], format!("{}\n", hex(&seed))).unwrap();
            let lits: Vec<String> = pubk.iter().map(|b| format!("0x{:02x}", b)).collect();
            fs::write(&a[2], format!("[{}]\n", lits.join(", "))).unwrap();
            fs::write(&a[3], format!("{}\n", hex(&pubk))).unwrap();
            println!("wrote {} (secret, dev only), {}, {}", a[1], a[2], a[3]);
        }
        Some("sign") => {
            let (mut seed_path, mut dir) = (None, None);
            let mut i = 1;
            while i < a.len() {
                if a[i] == "--seed" {
                    seed_path = Some(a[i + 1].clone());
                    i += 2;
                } else {
                    dir = Some(a[i].clone());
                    i += 1;
                }
            }
            let (seed_path, dir) = (seed_path.unwrap_or_else(|| die("--seed required")), dir.unwrap_or_else(|| die("dir required")));
            let seed: [u8; 32] = unhex(&fs::read_to_string(seed_path).unwrap()).try_into().unwrap_or_else(|_| die("seed must be 32 bytes"));
            let wasm = fs::read(format!("{dir}/app.wasm")).unwrap();
            let pol = fs::read(format!("{dir}/app.policy")).unwrap();
            let proof = fs::read(format!("{dir}/app.proof")).ok();
            let mut msg = [0u8; MSG_MAX];
            let n = signed_message(&pol, &wasm, proof.as_deref(), &mut msg);
            let sig = sign_ed25519(&seed, &msg[..n]);
            fs::write(format!("{dir}/app.sig"), format!("{}\n", hex(&sig))).unwrap();
            println!("signed {dir}/app.sig");
        }
        Some("bench") if a.len() >= 3 => {
            // qs bench <dir> <iterations> [--body S] [--query Q]   (host reference numbers; NOT seL4 numbers)
            let dir = &a[1];
            let iters: usize = a[2].parse().unwrap();
            let body = a.iter().position(|x| x == "--body").map(|i| a[i + 1].clone().into_bytes()).unwrap_or_default();
            let wasm = fs::read(format!("{dir}/app.wasm")).unwrap();
            let pol = fs::read(format!("{dir}/app.policy")).unwrap();
            let sig = fs::read(format!("{dir}/app.sig")).unwrap();
            let t = Instant::now();
            for _ in 0..(iters / 100).max(1) { std::hint::black_box(load(&wasm, &pol, &sig, None, &CODE_SIGNING_PUBLIC_KEY).unwrap()); }
            let verify_us = t.elapsed().as_secs_f64() * 1e6 / (iters / 100).max(1) as f64;
            let t = Instant::now();
            for _ in 0..iters { std::hint::black_box(pg_script::Module::parse(&wasm).unwrap()); }
            let parse_us = t.elapsed().as_secs_f64() * 1e6 / iters as f64;
            let vs = load(&wasm, &pol, &sig, None, &CODE_SIGNING_PUBLIC_KEY).unwrap();
            let mut kv = Kv::new();
            let mut mem = vec![0u8; 256 * 1024];
            let mut out = vec![0u8; 16 * 1024];
            let req = Request { method: if body.is_empty() { Method::Get } else { Method::Post }, path: b"/script/x", query: b"", content_type: b"", user_agent: b"", body: &body, principal: 0 };
            let t = Instant::now();
            let mut fuel = 0u64;
            for _ in 0..iters { let o = execute(vs.module(), vs.policy(), &req, &mut kv, &mut mem, &mut out, NoClock); fuel = o.fuel_used; std::hint::black_box(&o); }
            let el = t.elapsed();
            println!("{{\"dir\":\"{dir}\",\"iters\":{iters},\"exec_req_per_s\":{:.0},\"exec_us_per_req\":{:.2},\"fuel_per_req\":{fuel},\"module_parse_us\":{:.2},\"bundle_verify_us\":{:.0},\"size_of_instance_bytes\":{},\"wasm_bytes\":{}}}",
                iters as f64 / el.as_secs_f64(), el.as_secs_f64() * 1e6 / iters as f64, parse_us, verify_us, pg_script::wasm::size_of_instance(), wasm.len());
        }
        Some("mkproof") if a.len() == 3 => {
            // qs mkproof <MemorySafe|FuelBounded|HostApiSubset> <dir>: writes a *well-formed but unchecked* app.proof
            // envelope bound to app.wasm/app.policy. There is no checker, so the runtime will not rely on it.
            use pg_script_verify::proof::{build, Claim};
            let claim = match a[1].as_str() { "MemorySafe" => Claim::MemorySafe, "FuelBounded" => Claim::FuelBounded, "HostApiSubset" => Claim::HostApiSubset, _ => die("unknown claim") };
            let wasm = fs::read(format!("{}/app.wasm", a[2])).unwrap();
            let pol = fs::read(format!("{}/app.policy", a[2])).unwrap();
            let mut buf = vec![0u8; 1024];
            let n = build(claim, 0, &wasm, &pol, b"no-checker-yet", &mut buf);
            fs::write(format!("{}/app.proof", a[2]), &buf[..n]).unwrap();
            println!("wrote {}/app.proof ({} bytes, UNCHECKED claim {:?})", a[2], n, claim);
        }
        Some("pack") if a.len() >= 3 => {
            // qs pack <out.qsb> <dir>...   (embeds already-signed bundles; verification happens on the target)
            let dirs = &a[2..];
            let mut out = b"QSB1".to_vec();
            out.push(dirs.len() as u8);
            for d in dirs {
                let wasm = fs::read(format!("{d}/app.wasm")).unwrap();
                let pol = fs::read(format!("{d}/app.policy")).unwrap();
                let proof = fs::read(format!("{d}/app.proof")).unwrap_or_default();
                let sig = fs::read_to_string(format!("{d}/app.sig")).unwrap();
                let sig = sig.trim();
                assert_eq!(sig.len(), 128, "{d}/app.sig must be 128 hex chars");
                for l in [wasm.len(), pol.len(), proof.len()] {
                    out.extend_from_slice(&(l as u32).to_be_bytes());
                }
                out.extend_from_slice(sig.as_bytes());
                out.extend_from_slice(&wasm);
                out.extend_from_slice(&pol);
                out.extend_from_slice(&proof);
            }
            fs::write(&a[1], &out).unwrap();
            println!("packed {} bundle(s), {} bytes -> {}", dirs.len(), out.len(), a[1]);
        }
        Some("verify") | Some("run") => {
            let run = a[0] == "run";
            let mut pubk = CODE_SIGNING_PUBLIC_KEY;
            let (mut method, mut path, mut query, mut body, mut ct) = (Method::Get, String::new(), String::new(), Vec::new(), String::new());
            let (mut principal, mut repeat, mut mem_kb, mut dir) = (0u32, 1usize, 1024usize, None);
            let mut i = 1;
            while i < a.len() {
                let v = a.get(i + 1).cloned().unwrap_or_default();
                match a[i].as_str() {
                    "--pub" => { pubk = unhex(&fs::read_to_string(&v).unwrap()).try_into().unwrap_or_else(|_| die("bad pub")); i += 2 }
                    "--method" => { method = if v == "POST" { Method::Post } else { Method::Get }; i += 2 }
                    "--path" => { path = v; i += 2 }
                    "--query" => { query = v; i += 2 }
                    "--body" => { body = v.into_bytes(); i += 2 }
                    "--body-file" => { body = fs::read(&v).unwrap(); i += 2 }
                    "--content-type" => { ct = v; i += 2 }
                    "--principal" => { principal = v.parse().unwrap(); i += 2 }
                    "--repeat" => { repeat = v.parse().unwrap(); i += 2 }
                    "--mem-kb" => { mem_kb = v.parse().unwrap(); i += 2 }
                    _ => { dir = Some(a[i].clone()); i += 1 }
                }
            }
            let dir = dir.unwrap_or_else(|| die("dir required"));
            let wasm = fs::read(format!("{dir}/app.wasm")).unwrap_or_else(|_| die("missing app.wasm"));
            let pol = fs::read(format!("{dir}/app.policy")).unwrap_or_else(|_| die("missing app.policy"));
            let sig = fs::read(format!("{dir}/app.sig")).unwrap_or_default();
            let proof = fs::read(format!("{dir}/app.proof")).ok();
            let vs = match load(&wasm, &pol, &sig, proof.as_deref(), &pubk) {
                Ok(v) => v,
                Err(e) => { eprintln!("REJECTED: {e:?}"); exit(3) }
            };
            println!("OK module={} version={} admission={:?} proof={:?} proof_accepted={}",
                String::from_utf8_lossy(vs.policy().module_id), vs.policy().version, vs.admission(), vs.proof_status(), vs.proof_accepted());
            if !run { return; }
            let mut kv = Kv::new();
            let mut mem = vec![0u8; mem_kb * 1024];
            let mut out = vec![0u8; 64 * 1024];
            let t0 = Instant::now();
            let mut last = None;
            for _ in 0..repeat {
                let req = Request { method, path: path.as_bytes(), query: query.as_bytes(), content_type: ct.as_bytes(),
                    user_agent: b"", body: &body, principal };
                let o = if repeat == 1 {
                    execute(vs.module(), vs.policy(), &req, &mut kv, &mut mem, &mut out, WallClock(Instant::now()))
                } else {
                    execute(vs.module(), vs.policy(), &req, &mut kv, &mut mem, &mut out, NoClock)
                };
                last = Some(o);
            }
            let dt = t0.elapsed();
            let o = last.unwrap();
            println!("status={} content_type={} reason={:?} fuel={} body_len={}", o.status, pg_script::content_type_str(o.content_type), o.reason, o.fuel_used, o.body_len);
            println!("BODY:{}", String::from_utf8_lossy(&out[..o.body_len]));
            if repeat > 1 {
                println!("repeat={} total_us={} per_req_us={:.2} req_per_s={:.0}", repeat, dt.as_micros(), dt.as_secs_f64() * 1e6 / repeat as f64, repeat as f64 / dt.as_secs_f64());
            }
        }
        _ => die("usage: qs keygen|sign|verify|run ... (see crates/pg-script-cli/src/main.rs)"),
    }
}
