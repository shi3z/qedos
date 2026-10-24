//! `#![no_std]` Rust implementation for qedos seL4 Protection Domains:
//!   - `http_pd`: strict HTTP/1.1 request head + body parsing via `pg_http` (LAW_006, LAW_007)
//!   - `policy_pd`: Ed25519 signed config verification via `pg_config` (LAW_011) and
//!     fixed-route + path-hygiene evaluation via `pg_policy` (LAW_001, LAW_004, LAW_007)
//!   - `connector_pd`: canonical backend HTTP/1.1 request framing and strict response
//!     validation via `pg_http::parse_response` (LAW_004, LAW_006)
#![no_std]

use core::panic::PanicInfo;
use pg_config::{BackendSpec, MAX_BACKENDS, MAX_PATTERN_LEN, MAX_ROUTES, PUBLIC_KEY};
use pg_http::{parse_request, parse_response, reason_phrase, ChunkDecoder, Framing, Method};
use pg_policy::{decide, Action, BackendId, Decision, Pattern, Route};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// IPC decision shims (logic in the forbid(unsafe) crate pg-ipc; Kani-verified, see crates/pg-ipc/src/proofs.rs)
include!("../../../crates/pg-ipc/ffi/shims.rs");

fn method_from_u8(m: u8) -> Option<Method> {
    match m {
        0 => Some(Method::Get),
        1 => Some(Method::Head),
        2 => Some(Method::Post),
        3 => Some(Method::Put),
        4 => Some(Method::Delete),
        5 => Some(Method::Patch),
        6 => Some(Method::Options),
        _ => None,
    }
}

fn method_to_u8(m: Method) -> u8 {
    match m {
        Method::Get => 0,
        Method::Head => 1,
        Method::Post => 2,
        Method::Put => 3,
        Method::Delete => 4,
        Method::Patch => 5,
        Method::Options => 6,
    }
}

// ============================================================================
// 1. HTTP PD Logic (wraps `pg_http::parse_request` + `ChunkDecoder`)
// ============================================================================

/// Parse an HTTP/1.1 request (head + body) from `buf[..len]`.
///
/// Returns:
///   * `0`       — incomplete request head or body, need more bytes.
///   * `1`       — valid request parsed! Outputs written to out-pointers.
///   * `-status` — rejected with HTTP status (e.g. -400, -405, -413, -414, -417, -431, -501, -505).
#[no_mangle]
pub unsafe extern "C" fn pg_rust_parse_http_request(
    buf_ptr: *const u8,
    buf_len: usize,
    max_body_cap: usize,
    method_out: *mut u8,
    keep_alive_out: *mut u8,
    target_out: *mut u8,
    target_cap: usize,
    target_len_out: *mut u16,
    host_out: *mut u8,
    host_cap: usize,
    host_len_out: *mut u16,
    body_out: *mut u8,
    body_len_out: *mut u32,
    consumed_out: *mut usize,
) -> i32 {
    if buf_ptr.is_null() {
        return -400;
    }
    let buf = core::slice::from_raw_parts(buf_ptr, buf_len);
    let req = match parse_request(buf) {
        Ok(None) => return 0,
        Ok(Some(r)) => r,
        Err(e) => return -(e.status() as i32),
    };

    let target_slice = req.target.slice(buf);
    let host_slice = req.host.slice(buf);
    if target_slice.len() > target_cap || host_slice.len() > host_cap {
        return -414;
    }

    let after_head = &buf[req.head_len..];
    let mut decoded_body_len = 0usize;
    let total_consumed: usize;

    match req.framing {
        Framing::None => {
            total_consumed = req.head_len;
        }
        Framing::Length(n) => {
            if n > (max_body_cap as u64) {
                return -413;
            }
            let n_usize = n as usize;
            if after_head.len() < n_usize {
                return 0; // wait for full body
            }
            if !body_out.is_null() && n_usize > 0 {
                let dst = core::slice::from_raw_parts_mut(body_out, max_body_cap);
                dst[..n_usize].copy_from_slice(&after_head[..n_usize]);
            }
            decoded_body_len = n_usize;
            total_consumed = req.head_len + n_usize;
        }
        Framing::Chunked => {
            let mut dec = ChunkDecoder::new(max_body_cap as u64);
            let mut pos = 0usize;
            let dst = if !body_out.is_null() {
                core::slice::from_raw_parts_mut(body_out, max_body_cap)
            } else {
                &mut []
            };
            loop {
                if pos >= after_head.len() {
                    return 0; // need more chunk bytes
                }
                match dec.advance(&after_head[pos..]) {
                    Ok(adv) => {
                        if let Some(sp) = adv.data {
                            let chunk = &after_head[pos + sp.start..pos + sp.end];
                            if decoded_body_len + chunk.len() > dst.len() {
                                return -413;
                            }
                            dst[decoded_body_len..decoded_body_len + chunk.len()]
                                .copy_from_slice(chunk);
                            decoded_body_len += chunk.len();
                        }
                        pos += adv.consumed;
                        if adv.done {
                            total_consumed = req.head_len + pos;
                            break;
                        }
                        if adv.consumed == 0 {
                            return 0;
                        }
                    }
                    Err(pg_http::ChunkError::TooLarge) => return -413,
                    Err(pg_http::ChunkError::BadSize | pg_http::ChunkError::BadFraming) => return -400,
                }
            }
        }
        Framing::UntilClose => return -400,
    }

    if !method_out.is_null() {
        *method_out = method_to_u8(req.method);
    }
    if !keep_alive_out.is_null() {
        *keep_alive_out = if req.keep_alive { 1 } else { 0 };
    }
    if !target_out.is_null() {
        let dst = core::slice::from_raw_parts_mut(target_out, target_cap);
        dst[..target_slice.len()].copy_from_slice(target_slice);
    }
    if !target_len_out.is_null() {
        *target_len_out = target_slice.len() as u16;
    }
    if !host_out.is_null() {
        let dst = core::slice::from_raw_parts_mut(host_out, host_cap);
        dst[..host_slice.len()].copy_from_slice(host_slice);
    }
    if !host_len_out.is_null() {
        *host_len_out = host_slice.len() as u16;
    }
    if !body_len_out.is_null() {
        *body_len_out = decoded_body_len as u32;
    }
    if !consumed_out.is_null() {
        *consumed_out = total_consumed;
    }
    1
}

/// Format a minimal, canonical HTTP/1.1 response for local Health (`200`) or Reject (`4xx`/`5xx`).
#[no_mangle]
pub unsafe extern "C" fn pg_rust_format_local_response(
    status: u16,
    is_health: u8,
    is_head_method: u8,
    keep_alive: u8,
    out_ptr: *mut u8,
    out_cap: usize,
) -> usize {
    if out_ptr.is_null() || out_cap < 128 {
        return 0;
    }
    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    let mut pos = 0usize;

    let mut push = |s: &[u8]| {
        if pos + s.len() <= out.len() {
            out[pos..pos + s.len()].copy_from_slice(s);
            pos += s.len();
        }
    };

    push(b"HTTP/1.1 ");
    let d2 = b'0' + ((status / 100) % 10) as u8;
    let d1 = b'0' + ((status / 10) % 10) as u8;
    let d0 = b'0' + (status % 10) as u8;
    push(&[d2, d1, d0, b' ']);
    push(reason_phrase(status).as_bytes());
    push(b"\r\n");

    if is_health != 0 {
        push(b"Content-Type: text/plain\r\nContent-Length: 3\r\n");
        if keep_alive != 0 {
            push(b"Connection: keep-alive\r\n\r\n");
        } else {
            push(b"Connection: close\r\n\r\n");
        }
        if is_head_method == 0 {
            push(b"ok\n");
        }
    } else {
        push(b"Content-Type: text/plain\r\nContent-Length: 0\r\n");
        if keep_alive != 0 && status != 400 && status != 413 && status != 414 && status != 431 {
            push(b"Connection: keep-alive\r\n\r\n");
        } else {
            push(b"Connection: close\r\n\r\n");
        }
    }
    pos
}

// ============================================================================
// 2. Policy PD Logic (wraps `pg_config::verify_and_parse` + `pg_policy::decide`)
// ============================================================================

struct StoredRoute {
    method: Method,
    is_prefix: bool,
    pat_len: usize,
    pat_bytes: [u8; MAX_PATTERN_LEN],
    action: Action,
}

impl StoredRoute {
    const fn empty() -> Self {
        StoredRoute {
            method: Method::Get,
            is_prefix: false,
            pat_len: 0,
            pat_bytes: [0u8; MAX_PATTERN_LEN],
            action: Action::Health,
        }
    }
}

static mut POLICY_VALID: bool = false;
static mut POLICY_N_ROUTES: usize = 0;
static mut POLICY_ROUTES: [StoredRoute; MAX_ROUTES] = [const { StoredRoute::empty() }; MAX_ROUTES];
static mut POLICY_N_BACKENDS: usize = 0;
static mut POLICY_BACKENDS: [BackendSpec; MAX_BACKENDS] = [BackendSpec {
    ipv4: [0; 4],
    port: 0,
}; MAX_BACKENDS];

/// Verify the Ed25519-signed configuration blob in `blob_ptr[..blob_len]` against
/// the pinned `pg_config::PUBLIC_KEY` (LAW_011).
///
///Note: `blob_len` may be the 4096-byte shared memory region size; the binary format
/// encodes exact route lengths, or we determine the exact blob length from the header!
#[no_mangle]
pub unsafe extern "C" fn pg_rust_policy_init(
    blob_ptr: *const u8,
    max_len: usize,
    n_backends_out: *mut u8,
    backends_ipv4_out: *mut u8,
    backends_port_out: *mut u16,
) -> i32 {
    POLICY_VALID = false;
    if blob_ptr.is_null() || max_len < pg_config::HEADER_LEN + pg_config::SIGNATURE_LEN {
        return -1;
    }
    let raw = core::slice::from_raw_parts(blob_ptr, max_len);

    // Determine exact signed blob length from the self-delimiting PGS1 header + routes + 64B sig
    if &raw[0..4] != &pg_config::MAGIC {
        return -2;
    }
    let n_be = raw[5] as usize;
    let n_rt = raw[6] as usize;
    if n_be > MAX_BACKENDS || n_rt == 0 || n_rt > MAX_ROUTES {
        return -3;
    }
    let mut pos = pg_config::HEADER_LEN + n_be * 6;
    if pos > max_len {
        return -4;
    }
    let mut ri = 0usize;
    while ri < n_rt {
        if pos + 13 > max_len {
            return -5;
        }
        let pat_len = raw[pos + 12] as usize;
        pos += 13 + pat_len;
        if pos > max_len {
            return -6;
        }
        ri += 1;
    }
    let total_blob_len = pos + pg_config::SIGNATURE_LEN;
    if total_blob_len > max_len {
        return -7;
    }

    let cfg = match pg_config::verify_and_parse(&raw[..total_blob_len], &PUBLIC_KEY) {
        Ok(c) => c,
        Err(_) => return -10, // LAW_011: Ed25519 signature or format invalid!
    };

    POLICY_N_BACKENDS = cfg.n_backends;
    let mut bi = 0usize;
    while bi < cfg.n_backends {
        POLICY_BACKENDS[bi] = cfg.backends[bi];
        if !backends_ipv4_out.is_null() {
            let ip_dst = core::slice::from_raw_parts_mut(backends_ipv4_out.add(bi * 4), 4);
            ip_dst.copy_from_slice(&cfg.backends[bi].ipv4);
        }
        if !backends_port_out.is_null() {
            *backends_port_out.add(bi) = cfg.backends[bi].port;
        }
        bi += 1;
    }
    if !n_backends_out.is_null() {
        *n_backends_out = cfg.n_backends as u8;
    }

    POLICY_N_ROUTES = cfg.n_routes;
    let mut r = 0usize;
    while r < cfg.n_routes {
        let rt = cfg.routes[r];
        let (is_prefix, pat_slice) = match rt.pattern {
            Pattern::Exact(s) => (false, s),
            Pattern::Prefix(s) => (true, s),
        };
        POLICY_ROUTES[r].method = rt.method;
        POLICY_ROUTES[r].is_prefix = is_prefix;
        POLICY_ROUTES[r].pat_len = pat_slice.len();
        POLICY_ROUTES[r].pat_bytes[..pat_slice.len()].copy_from_slice(pat_slice);
        POLICY_ROUTES[r].action = rt.action;
        r += 1;
    }

    POLICY_VALID = true;
    cfg.n_routes as i32
}

/// Evaluate `pg_policy::decide` on a parsed request (LAW_001, LAW_004, LAW_007, LAW_011).
#[no_mangle]
pub unsafe extern "C" fn pg_rust_policy_decide(
    method_u8: u8,
    target_ptr: *const u8,
    target_len: usize,
    body_len: u32,
    decision_out: *mut u8,
    backend_id_out: *mut u8,
    reject_status_out: *mut u16,
) -> i32 {
    if !POLICY_VALID {
        if !decision_out.is_null() {
            *decision_out = 0; // PG_DECISION_REJECT
        }
        if !reject_status_out.is_null() {
            *reject_status_out = 503;
        }
        return 0;
    }
    let method = match method_from_u8(method_u8) {
        Some(m) => m,
        None => {
            *decision_out = 0;
            *reject_status_out = 501;
            return 0;
        }
    };
    let target = core::slice::from_raw_parts(target_ptr, target_len);

    // Reconstruct temporary Route slice pointing into POLICY_ROUTES
    let dummy = Route {
        method: Method::Get,
        pattern: Pattern::Exact(b"/"),
        action: Action::Health,
    };
    let mut routes = [dummy; MAX_ROUTES];
    let n = POLICY_N_ROUTES;
    let mut i = 0usize;
    while i < n {
        let sr = &POLICY_ROUTES[i];
        let pat_slice = &sr.pat_bytes[..sr.pat_len];
        let pattern = if sr.is_prefix {
            Pattern::Prefix(pat_slice)
        } else {
            Pattern::Exact(pat_slice)
        };
        routes[i] = Route {
            method: sr.method,
            pattern,
            action: sr.action,
        };
        i += 1;
    }

    match decide(&routes[..n], method, target) {
        Decision::Health => {
            if body_len > 0 {
                *decision_out = 0;
                *reject_status_out = 413;
            } else {
                *decision_out = 1; // PG_DECISION_HEALTH
                *reject_status_out = 200;
            }
        }
        Decision::Reject(status) => {
            *decision_out = 0; // PG_DECISION_REJECT
            *reject_status_out = status;
        }
        Decision::Forward {
            backend: BackendId(id),
            max_body,
        } => {
            if (body_len as u64) > max_body {
                *decision_out = 0; // PG_DECISION_REJECT
                *reject_status_out = 413;
            } else {
                *decision_out = 2; // PG_DECISION_FORWARD
                *backend_id_out = id;
                *reject_status_out = 200;
            }
        }
    }
    1
}

// ============================================================================
// 3. Connector PD Logic (canonical HTTP/1.1 framing + `pg_http::parse_response`)
// ============================================================================

fn format_u32_ascii(mut n: u32, buf: &mut [u8; 10]) -> &[u8] {
    if n == 0 {
        buf[9] = b'0';
        return &buf[9..10];
    }
    let mut i = 10usize;
    while n > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..10]
}

/// Construct a sanitized outbound HTTP/1.1 request for the fixed backend (`ipv4:port`).
/// Strips all client-supplied headers (Host, X-Forwarded-*, Forwarded, Via, Connection)
/// and emits only the canonical request line, fixed `Host`, `Connection: close`, and
/// `Content-Length` + body.
#[no_mangle]
pub unsafe extern "C" fn pg_rust_format_backend_request(
    method_u8: u8,
    target_ptr: *const u8,
    target_len: usize,
    backend_ipv4_ptr: *const u8,
    backend_port: u16,
    body_ptr: *const u8,
    body_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> usize {
    let method = match method_from_u8(method_u8) {
        Some(m) => m,
        None => return 0,
    };
    let target = core::slice::from_raw_parts(target_ptr, target_len);
    let ipv4 = core::slice::from_raw_parts(backend_ipv4_ptr, 4);
    let body = if body_len > 0 && !body_ptr.is_null() {
        core::slice::from_raw_parts(body_ptr, body_len)
    } else {
        &[]
    };
    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    let mut pos = 0usize;

    macro_rules! push {
        ($slice:expr) => {{
            let s: &[u8] = $slice;
            if pos + s.len() > out.len() {
                return 0;
            }
            out[pos..pos + s.len()].copy_from_slice(s);
            pos += s.len();
        }};
    }

    push!(method.as_str().as_bytes());
    push!(b" ");
    push!(target);
    push!(b" HTTP/1.1\r\nHost: ");

    let mut num_buf = [0u8; 10];
    push!(format_u32_ascii(ipv4[0] as u32, &mut num_buf));
    push!(b".");
    push!(format_u32_ascii(ipv4[1] as u32, &mut num_buf));
    push!(b".");
    push!(format_u32_ascii(ipv4[2] as u32, &mut num_buf));
    push!(b".");
    push!(format_u32_ascii(ipv4[3] as u32, &mut num_buf));
    push!(b":");
    push!(format_u32_ascii(backend_port as u32, &mut num_buf));
    push!(b"\r\nConnection: close\r\n");

    if !body.is_empty() || matches!(method, Method::Post | Method::Put | Method::Patch) {
        push!(b"Content-Length: ");
        push!(format_u32_ascii(body.len() as u32, &mut num_buf));
        push!(b"\r\n");
    }
    push!(b"\r\n");
    if !body.is_empty() {
        push!(body);
    }
    pos
}

/// Validate a raw backend HTTP response using `pg_http::parse_response` (LAW_006)
/// and reframe it cleanly for the client with an explicit `Content-Length` and
/// `Connection: keep-alive` or `Connection: close`.
#[no_mangle]
pub unsafe extern "C" fn pg_rust_validate_and_frame_response(
    raw_ptr: *const u8,
    raw_len: usize,
    is_head_req: u8,
    keep_alive: u8,
    status_out: *mut u16,
    out_ptr: *mut u8,
    out_cap: usize,
) -> usize {
    let raw = core::slice::from_raw_parts(raw_ptr, raw_len);
    let head_req = is_head_req != 0;

    let resp = match parse_response(raw, head_req) {
        Ok(Some(r)) => r,
        _ => {
            if !status_out.is_null() {
                *status_out = 502;
            }
            return pg_rust_format_local_response(502, 0, is_head_req, 0, out_ptr, out_cap);
        }
    };

    let after_head = &raw[resp.head_len..];
    // Extract or decode response body
    let mut body_buf = [0u8; 16384];
    let body_slice: &[u8];

    match resp.framing {
        Framing::None => {
            body_slice = &[];
        }
        Framing::Length(n) => {
            let n_usize = n as usize;
            if after_head.len() < n_usize {
                if !status_out.is_null() {
                    *status_out = 502;
                }
                return pg_rust_format_local_response(502, 0, is_head_req, 0, out_ptr, out_cap);
            }
            body_slice = &after_head[..n_usize];
        }
        Framing::UntilClose => {
            body_slice = after_head;
        }
        Framing::Chunked => {
            let mut dec = ChunkDecoder::new(body_buf.len() as u64);
            let mut pos = 0usize;
            let mut dlen = 0usize;
            loop {
                if pos >= after_head.len() {
                    if !status_out.is_null() {
                        *status_out = 502;
                    }
                    return pg_rust_format_local_response(502, 0, is_head_req, 0, out_ptr, out_cap);
                }
                match dec.advance(&after_head[pos..]) {
                    Ok(adv) => {
                        if let Some(sp) = adv.data {
                            let c = &after_head[pos + sp.start..pos + sp.end];
                            if dlen + c.len() > body_buf.len() {
                                if !status_out.is_null() {
                                    *status_out = 502;
                                }
                                return pg_rust_format_local_response(
                                    502,
                                    0,
                                    is_head_req,
                                    0,
                                    out_ptr,
                                    out_cap,
                                );
                            }
                            body_buf[dlen..dlen + c.len()].copy_from_slice(c);
                            dlen += c.len();
                        }
                        pos += adv.consumed;
                        if adv.done {
                            break;
                        }
                        if adv.consumed == 0 {
                            if !status_out.is_null() {
                                *status_out = 502;
                            }
                            return pg_rust_format_local_response(
                                502,
                                0,
                                is_head_req,
                                0,
                                out_ptr,
                                out_cap,
                            );
                        }
                    }
                    Err(_) => {
                        if !status_out.is_null() {
                            *status_out = 502;
                        }
                        return pg_rust_format_local_response(
                            502,
                            0,
                            is_head_req,
                            0,
                            out_ptr,
                            out_cap,
                        );
                    }
                }
            }
            body_slice = &body_buf[..dlen];
        }
    }

    if !status_out.is_null() {
        *status_out = resp.status;
    }

    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    let mut pos = 0usize;
    macro_rules! push {
        ($slice:expr) => {{
            let s: &[u8] = $slice;
            if pos + s.len() > out.len() {
                return 0;
            }
            out[pos..pos + s.len()].copy_from_slice(s);
            pos += s.len();
        }};
    }

    push!(b"HTTP/1.1 ");
    let d2 = b'0' + ((resp.status / 100) % 10) as u8;
    let d1 = b'0' + ((resp.status / 10) % 10) as u8;
    let d0 = b'0' + (resp.status % 10) as u8;
    push!(&[d2, d1, d0, b' ']);
    push!(reason_phrase(resp.status).as_bytes());
    push!(b"\r\n");

    // Forward safe backend headers (excluding hop-by-hop headers)
    for h in resp.headers() {
        let name = h.name.slice(raw);
        let val = h.value.slice(raw);
        if pg_http::eq_ignore_case(name, b"connection")
            || pg_http::eq_ignore_case(name, b"transfer-encoding")
            || pg_http::eq_ignore_case(name, b"content-length")
            || pg_http::eq_ignore_case(name, b"keep-alive")
            || pg_http::eq_ignore_case(name, b"upgrade")
        {
            continue;
        }
        push!(name);
        push!(b": ");
        push!(val);
        push!(b"\r\n");
    }

    let mut num_buf = [0u8; 10];
    if resp.status != 204 && resp.status != 304 {
        push!(b"Content-Length: ");
        push!(format_u32_ascii(body_slice.len() as u32, &mut num_buf));
        push!(b"\r\n");
    }
    if keep_alive != 0 {
        push!(b"Connection: keep-alive\r\n\r\n");
    } else {
        push!(b"Connection: close\r\n\r\n");
    }
    if !head_req && !body_slice.is_empty() {
        push!(body_slice);
    }
    pos
}

// ============================================================================
// 5. QED Script glue used by policy_pd / http_pd (only the small route + response-format pieces;
//    the Wasm interpreter itself is NOT linked into these PDs — see sel4/rust_script).
// ============================================================================

/// 1 iff `target` is a valid `/script/<module>` request for a GET/POST (LAW_001 path hygiene applies).
#[no_mangle]
pub unsafe extern "C" fn pg_rust_is_script_route(method_u8: u8, target_ptr: *const u8, target_len: usize) -> u8 {
    if target_ptr.is_null() {
        return 0;
    }
    let method = match method_from_u8(method_u8) {
        Some(m) => m,
        None => return 0,
    };
    let target = core::slice::from_raw_parts(target_ptr, target_len);
    pg_script_policy::route::script_route(method, target).is_some() as u8
}

/// Frame a script result as an HTTP/1.1 response. The head is built from fixed strings; the only
/// script-controlled inputs are the status (re-validated here: 200..=599, body-less statuses must have an empty body), a
/// 3-valued content-type selector, and the body bytes, so header injection is impossible.
#[no_mangle]
pub unsafe extern "C" fn pg_rust_format_script_response(
    status: u16,
    ctype: u8,
    keep_alive: u8,
    body_ptr: *const u8,
    body_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> usize {
    // 1xx (interim) and body-less statuses with a body would desynchronise the client's HTTP framing.
    if out_ptr.is_null()
        || (body_len > 0 && body_ptr.is_null())
        || !(200..=599).contains(&status)
        || (matches!(status, 204 | 205 | 304) && body_len > 0)
    {
        return 0;
    }
    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    let body: &[u8] = if body_len == 0 { &[] } else { core::slice::from_raw_parts(body_ptr, body_len) };
    let mut pos = 0usize;
    let mut ok = true;
    let mut push = |s: &[u8]| {
        if ok && pos + s.len() <= out.len() {
            out[pos..pos + s.len()].copy_from_slice(s);
            pos += s.len();
        } else {
            ok = false;
        }
    };
    push(b"HTTP/1.1 ");
    push(&[b'0' + ((status / 100) % 10) as u8, b'0' + ((status / 10) % 10) as u8, b'0' + (status % 10) as u8, b' ']);
    push(reason_phrase(status).as_bytes());
    push(b"\r\nContent-Type: ");
    push(match ctype {
        1 => b"text/html; charset=utf-8",
        2 => b"text/plain; charset=utf-8",
        _ => b"application/json",
    });
    push(b"\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; sandbox\r\nContent-Length: ");
    let mut num = [0u8; 10];
    push(format_u32_ascii(body.len() as u32, &mut num));
    push(if keep_alive != 0 { b"\r\nConnection: keep-alive\r\n\r\n" } else { b"\r\nConnection: close\r\n\r\n" });
    push(body);
    if ok { pos } else { 0 }
}

/// A fixed, hardcoded 301 redirect to `/press/index.html`, used only for the exact root path `/`.
/// No caller-supplied target or Location ever reaches this function -- the destination is a
/// compile-time constant, so there is no header-injection surface here at all.
#[no_mangle]
pub unsafe extern "C" fn pg_rust_format_root_redirect_response(
    keep_alive: u8,
    out_ptr: *mut u8,
    out_cap: usize,
) -> usize {
    if out_ptr.is_null() {
        return 0;
    }
    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    let mut pos = 0usize;
    let mut ok = true;
    let mut push = |s: &[u8]| {
        if ok && pos + s.len() <= out.len() {
            out[pos..pos + s.len()].copy_from_slice(s);
            pos += s.len();
        } else {
            ok = false;
        }
    };
    push(b"HTTP/1.1 301 Moved Permanently\r\nLocation: /press/index.html\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n");
    push(if keep_alive != 0 { b"Connection: keep-alive\r\n\r\n" } else { b"Connection: close\r\n\r\n" });
    if ok { pos } else { 0 }
}

// ============================================================================
// 6. QEDOS Press glue used by policy_pd / http_pd (only the route-prefix check and response
//    formatter; the signed-bundle verifier and lookup live in sel4/rust_press, linked ONLY into
//    qedos_press_pd -- see that crate).
// ============================================================================

/// 1 iff `target` starts with the `/press` mount prefix (LAW-style path hygiene: exact prefix match
/// only, no normalization games -- `policy_pd` forwards the request unchanged to qedos_press_pd,
/// which does its own full lookup against the signed manifest).
#[no_mangle]
pub unsafe extern "C" fn pg_rust_is_press_route(target_ptr: *const u8, target_len: usize) -> u8 {
    if target_ptr.is_null() {
        return 0;
    }
    let target = core::slice::from_raw_parts(target_ptr, target_len);
    (target.len() >= 6 && &target[..6] == b"/press" && (target.len() == 6 || target[6] == b'/')) as u8
}

/// Frame a QEDOS Press result as an HTTP/1.1 response. Mirrors `pg_rust_format_script_response`'s
/// injection-safety argument (fixed strings + re-validated status + a small closed content-type
/// selector), extended with the 6 content types static files need and a separate `content_len` for
/// HEAD responses (whose `body_len` is always 0 but whose `Content-Length` must reflect the real
/// resource size).
#[no_mangle]
pub unsafe extern "C" fn pg_rust_format_press_response(
    status: u16,
    ctype: u8,
    keep_alive: u8,
    body_ptr: *const u8,
    body_len: usize,
    content_len: u32,
    out_ptr: *mut u8,
    out_cap: usize,
) -> usize {
    if out_ptr.is_null()
        || (body_len > 0 && body_ptr.is_null())
        || !(200..=599).contains(&status)
        || (matches!(status, 204 | 205 | 304) && body_len > 0)
    {
        return 0;
    }
    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    let body: &[u8] = if body_len == 0 { &[] } else { core::slice::from_raw_parts(body_ptr, body_len) };
    let reported_len: u32 = if status == 200 { content_len } else { body.len() as u32 };
    let mut pos = 0usize;
    let mut ok = true;
    let mut push = |s: &[u8]| {
        if ok && pos + s.len() <= out.len() {
            out[pos..pos + s.len()].copy_from_slice(s);
            pos += s.len();
        } else {
            ok = false;
        }
    };
    push(b"HTTP/1.1 ");
    push(&[b'0' + ((status / 100) % 10) as u8, b'0' + ((status / 10) % 10) as u8, b'0' + (status % 10) as u8, b' ']);
    push(pg_http::reason_phrase(status).as_bytes());
    push(b"\r\nContent-Type: ");
    push(match ctype {
        0 => b"text/html; charset=utf-8" as &[u8],
        1 => b"text/css; charset=utf-8",
        2 => b"application/javascript; charset=utf-8",
        3 => b"application/json",
        5 => b"application/octet-stream",
        _ => b"text/plain; charset=utf-8",
    });
    push(b"\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; sandbox\r\nContent-Length: ");
    let mut num = [0u8; 10];
    push(format_u32_ascii(reported_len, &mut num));
    push(if keep_alive != 0 { b"\r\nConnection: keep-alive\r\n\r\n" } else { b"\r\nConnection: close\r\n\r\n" });
    push(body);
    if ok { pos } else { 0 }
}

/// Frame a QEDOS Press PQ-wrap result (POST /press/pq-fetch). The outer HTTP status is always 200
/// (this PD's job is only to deliver the AEAD envelope byte-for-byte; the real application status
/// travels INSIDE the encrypted/authenticated payload, decoded client-side after decryption, not
/// reflected into any header here). Body wire format: [2 bytes app_status, big-endian][12 bytes
/// AES-GCM nonce][ciphertext || 16-byte tag]. No caller-supplied string data is ever placed in this
/// response -- every byte other than the opaque nonce/ciphertext is a fixed constant.
#[no_mangle]
pub unsafe extern "C" fn pg_rust_format_pq_response(
    app_status: u16,
    keep_alive: u8,
    nonce_ptr: *const u8,
    ciphertext_ptr: *const u8,
    ciphertext_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> usize {
    if out_ptr.is_null() || nonce_ptr.is_null() || (ciphertext_len > 0 && ciphertext_ptr.is_null()) {
        return 0;
    }
    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    let nonce = core::slice::from_raw_parts(nonce_ptr, 12);
    let ciphertext: &[u8] = if ciphertext_len == 0 { &[] } else { core::slice::from_raw_parts(ciphertext_ptr, ciphertext_len) };
    let body_len = 2usize + 12usize + ciphertext.len();
    let mut pos = 0usize;
    let mut ok = true;
    let mut push = |s: &[u8]| {
        if ok && pos + s.len() <= out.len() {
            out[pos..pos + s.len()].copy_from_slice(s);
            pos += s.len();
        } else {
            ok = false;
        }
    };
    push(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; sandbox\r\nContent-Length: ");
    let mut num = [0u8; 10];
    push(format_u32_ascii(body_len as u32, &mut num));
    push(if keep_alive != 0 { b"\r\nConnection: keep-alive\r\n\r\n" } else { b"\r\nConnection: close\r\n\r\n" });
    push(&[(app_status >> 8) as u8, (app_status & 0xff) as u8]);
    push(nonce);
    push(ciphertext);
    if ok { pos } else { 0 }
}
