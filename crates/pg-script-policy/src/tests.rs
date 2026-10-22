use super::*;

const GOOD: &str = "runtime = qs-wasm/1\nmodule = m1\nversion = 3\nallow = resp_write\nmax_memory_bytes = 65536\nmax_fuel = 1000\nmax_stack_depth = 4\nmax_request_bytes = 100\nmax_response_bytes = 100\nmax_host_calls = 10\nmax_exec_us = 1000\n";

fn with(extra: &str) -> std::string::String {
    std::format!("{GOOD}{extra}")
}
fn parse(s: &str) -> Result<Policy<'_>, PolicyError> {
    Policy::parse(s.as_bytes())
}

extern crate std;

#[test]
fn good_policy_parses() {
    let p = parse(GOOD).unwrap();
    assert_eq!(p.module_id, b"m1");
    assert_eq!(p.version, 3);
    assert!(p.allows(Api::RespWrite));
    assert!(!p.allows(Api::KvGet));
    assert_eq!(p.limits.max_fuel, 1000);
}

#[test]
fn rejects_malformed_policies() {
    assert_eq!(parse(&with("bogus = 1\n")).unwrap_err(), PolicyError::UnknownKey);
    assert_eq!(parse(&with("max_fuel = 5\n")).unwrap_err(), PolicyError::DuplicateKey);
    assert_eq!(parse(&with("allow = resp_write\n")).unwrap_err(), PolicyError::DuplicateKey);
    assert_eq!(parse(&with("allow = system\n")).unwrap_err(), PolicyError::UnknownApi);
    assert_eq!(parse(&GOOD.replace("max_fuel = 1000", "max_fuel = 50000001")).unwrap_err(), PolicyError::ExceedsCeiling);
    assert_eq!(parse(&GOOD.replace("max_fuel = 1000", "max_fuel = 0")).unwrap_err(), PolicyError::ZeroLimit);
    assert_eq!(parse(&GOOD.replace("max_fuel = 1000", "max_fuel = 99999999999")).unwrap_err(), PolicyError::BadNumber);
    assert_eq!(parse(&GOOD.replace("max_fuel = 1000\n", "")).unwrap_err(), PolicyError::MissingKey);
    assert_eq!(parse(&GOOD.replace("qs-wasm/1", "qs-wasm/2")).unwrap_err(), PolicyError::BadRuntime);
    assert_eq!(parse(&GOOD.replace("module = m1", "module = M 1")).unwrap_err(), PolicyError::BadModuleId);
    assert_eq!(parse(&with("garbage line\n")).unwrap_err(), PolicyError::BadLine);
    assert_eq!(parse(&with("allow = kv_get\n")).unwrap_err(), PolicyError::Contradiction);
    assert_eq!(parse(&with("kv_read = a/\n")).unwrap_err(), PolicyError::Contradiction);
    assert_eq!(parse(&with("\u{1}")).unwrap_err(), PolicyError::NotUtf8Ascii);
}

#[test]
fn ceilings_are_enforced_for_every_limit() {
    for (k, over) in [
        ("max_memory_bytes = 65536", CEIL_MEMORY_BYTES as u64 + 1),
        ("max_stack_depth = 4", CEIL_STACK_DEPTH as u64 + 1),
        ("max_request_bytes = 100", CEIL_REQUEST_BYTES as u64 + 1),
        ("max_response_bytes = 100", CEIL_RESPONSE_BYTES as u64 + 1),
        ("max_host_calls = 10", CEIL_HOST_CALLS as u64 + 1),
        ("max_exec_us = 1000", CEIL_EXEC_US as u64 + 1),
    ] {
        let key = k.split(" =").next().unwrap();
        let t = GOOD.replace(k, &std::format!("{key} = {over}"));
        assert_eq!(parse(&t).unwrap_err(), PolicyError::ExceedsCeiling, "{key}");
    }
}

fn kvp() -> std::string::String {
    with("allow = kv_get\nallow = kv_put\nallow = kv_delete\nkv_read = a/\nkv_write = a/\n")
}

#[test]
fn kv_requires_principal_and_prefix() {
    let t = kvp();
    let p = parse(&t).unwrap();
    let mut kv = Kv::new();
    let mut buf = [0u8; 16];
    assert_eq!(kv.put(&p, 0, b"a/x", b"v"), Err(KvError::Unauthenticated));
    assert_eq!(kv.get(&p, 0, b"a/x", &mut buf), Err(KvError::Unauthenticated));
    assert_eq!(kv.put(&p, 5, b"b/x", b"v"), Err(KvError::Denied));
    assert_eq!(kv.put(&p, 5, b"a/x", b"v"), Ok(()));
    assert_eq!(kv.get(&p, 5, b"a/x", &mut buf), Ok(1));
    assert_eq!(&buf[..1], b"v");
    assert_eq!(kv.get(&p, 5, b"b/x", &mut buf), Err(KvError::Denied));
    assert_eq!(kv.get(&p, 5, b"../a/x", &mut buf), Err(KvError::Denied));
    assert_eq!(kv.get(&p, 5, b"a/\0x", &mut buf), Err(KvError::Denied));
}

#[test]
fn kv_isolates_principals_and_modules() {
    let t1 = kvp();
    let t2 = kvp().replace("module = m1", "module = m2");
    let (p1, p2) = (parse(&t1).unwrap(), parse(&t2).unwrap());
    let mut kv = Kv::new();
    let mut buf = [0u8; 16];
    kv.put(&p1, 1, b"a/k", b"one").unwrap();
    assert_eq!(kv.get(&p1, 2, b"a/k", &mut buf), Err(KvError::NotFound), "other principal");
    assert_eq!(kv.get(&p2, 1, b"a/k", &mut buf), Err(KvError::NotFound), "other module");
    assert_eq!(kv.delete(&p1, 2, b"a/k"), Err(KvError::NotFound));
    assert_eq!(kv.delete(&p2, 1, b"a/k"), Err(KvError::NotFound));
    assert_eq!(kv.get(&p1, 1, b"a/k", &mut buf), Ok(3));
    kv.delete(&p1, 1, b"a/k").unwrap();
    assert_eq!(kv.get(&p1, 1, b"a/k", &mut buf), Err(KvError::NotFound));
}

#[test]
fn kv_quota_prevents_namespace_starvation() {
    let t = kvp();
    let p = parse(&t).unwrap();
    let mut kv = Kv::new();
    for i in 0..KV_NS_QUOTA {
        let k = std::format!("a/{i}");
        kv.put(&p, 1, k.as_bytes(), b"x").unwrap();
    }
    assert_eq!(kv.put(&p, 1, b"a/over", b"x"), Err(KvError::Full));
    // another principal still has room
    assert_eq!(kv.put(&p, 2, b"a/ok", b"x"), Ok(()));
    // overwriting an existing key is not blocked by the quota
    assert_eq!(kv.put(&p, 1, b"a/0", b"y"), Ok(()));
    assert_eq!(kv.put(&p, 1, b"a/big", &[0u8; MAX_VAL_LEN + 1]), Err(KvError::ValueTooLong));
}

#[test]
fn namespaced_keys_are_injective_on_samples() {
    let mods: [&[u8]; 3] = [b"a", b"a.b", b"ab"];
    let keys: [&[u8]; 4] = [b"b", b"b/c", b"x", b"/b"];
    let mut seen = std::vec::Vec::new();
    for pr in [1u32, 2, 0x0100_0000, 0x0000_0100] {
        for m in mods {
            for k in keys {
                let mut o = [0u8; NS_KEY_LEN];
                let n = namespaced_key(pr, m, k, &mut o);
                let v = o[..n].to_vec();
                assert!(!seen.contains(&v));
                seen.push(v);
            }
        }
    }
}

/// Exhaustive over all modules (len 1..=3) and keys (len 1..=3) on a 3-letter alphabet plus a few
/// principals: no two distinct (principal, module, key) triples share a storage key.
#[test]
fn namespaced_keys_injective_exhaustive_small_alphabet() {
    fn strings(max: usize) -> std::vec::Vec<std::vec::Vec<u8>> {
        let mut all = std::vec::Vec::new();
        let mut cur: std::vec::Vec<std::vec::Vec<u8>> = std::vec![std::vec::Vec::new()];
        for _ in 0..max {
            let mut next = std::vec::Vec::new();
            for s in &cur {
                for c in [b'a', b'b', b'/'] {
                    let mut t = s.clone();
                    t.push(c);
                    next.push(t);
                }
            }
            all.extend(next.iter().cloned());
            cur = next;
        }
        all
    }
    let ss = strings(3);
    let mut seen = std::collections::HashMap::new();
    for pr in [1u32, 2, 256, 0x0100_0000] {
        for m in &ss {
            for k in &ss {
                let mut o = [0u8; NS_KEY_LEN];
                let n = namespaced_key(pr, m, k, &mut o);
                let prev = seen.insert(o[..n].to_vec(), (pr, m.clone(), k.clone()));
                assert!(prev.is_none(), "collision: {prev:?} vs {:?}", (pr, m, k));
            }
        }
    }
}

#[test]
fn script_routes_use_policy_hygiene() {
    use pg_http::Method;
    let r = route::script_route(Method::Get, b"/script/hello").unwrap();
    assert_eq!((r.module, r.path, r.query), (&b"hello"[..], &b"/script/hello"[..], &b""[..]));
    let r = route::script_route(Method::Post, b"/script/json-echo/x?a=1").unwrap();
    assert_eq!((r.module, r.query), (&b"json-echo"[..], &b"a=1"[..]));
    for bad in [
        &b"/script/"[..], b"/script", b"/scripts/hello", b"/script/../health", b"/script/%2e%2e/x", b"/script/a%2fb",
        b"/script/a;b", b"//script/hello", b"/script/hello/..", b"/script/\x00", b"/script/a\\b", b"/other/hello",
    ] {
        assert!(route::script_route(Method::Get, bad).is_none(), "{:?}", std::string::String::from_utf8_lossy(bad));
    }
    assert!(route::script_route(Method::Put, b"/script/hello").is_none());
    assert!(route::script_route(Method::Delete, b"/script/hello").is_none());
    let long = std::format!("/script/{}", "a".repeat(40));
    assert!(route::script_route(Method::Get, long.as_bytes()).is_none());
}
