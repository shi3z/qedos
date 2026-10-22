//! Restricted host API and the per-request execution driver.
//!
//! The guest can reach exactly the functions in [`pg_script_policy::Api`] that (a) the module imports,
//! (b) the signed policy allows, and (c) the linker resolves. Nothing else exists: there is no
//! clock, filesystem, socket, randomness, environment or inter-PD messaging API (LAW_015, LAW_022).
//! Every call re-checks the policy (defence in depth).

use crate::wasm::{FuncType, Host, Instance, LoadError, Memory, Module, Trap};
use pg_script_policy::{Api, Kv, KvError, Limits, Policy};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// Fields extracted by the trusted HTTP/Policy PDs. `principal` is the authenticated identity
/// established *outside* the script (0 = anonymous). The script cannot set or choose it.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub method: Method,
    pub path: &'a [u8],
    pub query: &'a [u8],
    pub content_type: &'a [u8],
    pub user_agent: &'a [u8],
    pub body: &'a [u8],
    pub principal: u32,
}

/// Monotonic clock supplied by the PD (seL4 timer client). Elapsed time since request start.
pub trait Clock {
    fn elapsed_us(&mut self) -> u64;
}

/// A clock that never advances (tests / environments without a timer; fuel still bounds execution).
pub struct NoClock;
impl Clock for NoClock {
    fn elapsed_us(&mut self) -> u64 {
        0
    }
}

/// Internal reason for operator logs. NEVER placed in the HTTP response (LAW_018).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Ok,
    RequestTooLarge,
    Load(LoadError),
    Trap(Trap),
    ScriptExit(i32),
    ResponseTooLarge,
    BadStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub status: u16,
    /// 0 = application/json, 1 = text/html, 2 = text/plain
    pub content_type: u8,
    pub body_len: usize,
    pub reason: Reason,
    pub fuel_used: u64,
}

pub const CT_JSON: u8 = 0;
pub const CT_HTML: u8 = 1;
pub const CT_TEXT: u8 = 2;

pub fn content_type_str(ct: u8) -> &'static str {
    match ct {
        CT_HTML => "text/html; charset=utf-8",
        CT_TEXT => "text/plain; charset=utf-8",
        _ => "application/json",
    }
}

const GENERIC_ERROR: &[u8] = b"{\"error\":\"script error\"}";

struct Ctx<'r, 'p, 'o, 'k, C: Clock> {
    policy: &'p Policy<'p>,
    req: &'r Request<'r>,
    out: &'o mut [u8],
    out_len: usize,
    out_cap: usize,
    status: u16,
    ctype: u8,
    overflow: bool,
    kv: &'k mut Kv,
    clock: C,
}

impl<'r, 'p, 'o, 'k, C: Clock> Host for Ctx<'r, 'p, 'o, 'k, C> {
    fn elapsed_us(&mut self) -> u64 {
        self.clock.elapsed_us()
    }

    fn call(&mut self, id: u8, a: &[i32], mem: &mut Memory<'_>) -> Result<Option<i32>, Trap> {
        let api = Api::from_id(id).ok_or(Trap::HostDenied)?;
        if !self.policy.allows(api) {
            return Err(Trap::HostDenied);
        }
        match api {
            Api::ReqMethod => Ok(Some(match self.req.method {
                Method::Get => 0,
                Method::Post => 2,
            })),
            Api::ReqField => {
                let src: &[u8] = match a[0] {
                    0 => self.req.path,
                    1 => self.req.query,
                    2 => self.req.body,
                    3 => self.req.content_type,
                    4 => self.req.user_agent,
                    _ => return Ok(Some(-1)),
                };
                let dst = match mem.slice_mut(a[1], a[2]) {
                    Ok(d) => d,
                    Err(_) => return Ok(Some(-1)),
                };
                let n = core::cmp::min(src.len(), dst.len());
                dst[..n].copy_from_slice(&src[..n]);
                Ok(Some(src.len() as i32))
            }
            Api::RespStatus => {
                if !(200..=599).contains(&a[0]) {
                    return Err(Trap::HostDenied);
                }
                self.status = a[0] as u16;
                Ok(None)
            }
            Api::RespContentType => {
                if !(0..=2).contains(&a[0]) {
                    return Err(Trap::HostDenied);
                }
                self.ctype = a[0] as u8;
                Ok(None)
            }
            Api::RespWrite => {
                let src = mem.slice(a[0], a[1])?;
                if src.len() > self.out_cap - self.out_len {
                    self.overflow = true;
                    return Err(Trap::HostDenied);
                }
                self.out[self.out_len..self.out_len + src.len()].copy_from_slice(src);
                self.out_len += src.len();
                Ok(None)
            }
            Api::KvGet => {
                let key = mem.slice(a[0], a[1])?;
                // copy key out so we can mutably borrow the value window afterwards
                let mut kb = [0u8; pg_script_policy::MAX_KEY_LEN];
                let klen = key.len();
                if klen > kb.len() {
                    return Ok(Some(-1));
                }
                kb[..klen].copy_from_slice(key);
                let dst = mem.slice_mut(a[2], a[3])?;
                match self.kv.get(self.policy, self.req.principal, &kb[..klen], dst) {
                    Ok(n) => Ok(Some(n as i32)),
                    Err(KvError::NotFound) => Ok(Some(-2)),
                    Err(_) => Ok(Some(-1)),
                }
            }
            Api::KvPut => {
                let key = mem.slice(a[0], a[1])?;
                let val = mem.slice(a[2], a[3])?;
                match self.kv.put(self.policy, self.req.principal, key, val) {
                    Ok(()) => Ok(Some(0)),
                    Err(_) => Ok(Some(-1)),
                }
            }
            Api::KvDelete => {
                let key = mem.slice(a[0], a[1])?;
                match self.kv.delete(self.policy, self.req.principal, key) {
                    Ok(()) => Ok(Some(0)),
                    Err(KvError::NotFound) => Ok(Some(-2)),
                    Err(_) => Ok(Some(-1)),
                }
            }
        }
    }
}

/// Resolver used for linking: only `qs.<api>` imports with the exact signature, allowed by the policy.
pub fn resolver<'p>(policy: &'p Policy<'p>) -> impl Fn(&[u8], &[u8], FuncType) -> Option<u8> + 'p {
    move |module, name, ty| {
        if module != b"qs" {
            return None;
        }
        let api = Api::from_name(name)?;
        if !policy.allows(api) {
            return None;
        }
        let (np, nr) = api.signature();
        if ty.n_params != np || ty.n_results != nr || !ty.all_i32() {
            return None;
        }
        Some(api as u8)
    }
}

fn fail(out: &mut [u8], status: u16, reason: Reason, fuel_used: u64) -> Outcome {
    // Discard anything the failed script managed to write before the generic error body.
    let mut z = 0;
    while z < out.len() {
        out[z] = 0;
        z += 1;
    }
    let n = core::cmp::min(GENERIC_ERROR.len(), out.len());
    out[..n].copy_from_slice(&GENERIC_ERROR[..n]);
    Outcome { status, content_type: CT_JSON, body_len: n, reason, fuel_used }
}

/// Execute one request against an already verified module. Fresh instance, fresh memory, fresh
/// response state every call (LAW_019); error details never reach the client (LAW_018).
///
/// * `mem`: scratch linear memory (zeroed here; scrubbed again when the instance drops).
/// * `out`: response body buffer (zeroed here). `out.len()` should be >= `policy.limits.max_response_bytes`;
///   the effective cap is the smaller of the two.
pub fn execute<C: Clock>(
    module: &Module<'_>,
    policy: &Policy<'_>,
    req: &Request<'_>,
    kv: &mut Kv,
    mem: &mut [u8],
    out: &mut [u8],
    clock: C,
) -> Outcome {
    let l: Limits = policy.limits;
    let mut z = 0;
    while z < out.len() {
        out[z] = 0;
        z += 1;
    }
    let req_len = req.path.len() + req.query.len() + req.body.len() + req.content_type.len() + req.user_agent.len();
    if req_len as u64 > l.max_request_bytes as u64 {
        return fail(out, 413, Reason::RequestTooLarge, 0);
    }
    let cap = core::cmp::min(out.len(), l.max_response_bytes as usize);
    let mut inst = match Instance::new(module, mem, l, resolver(policy)) {
        Ok(i) => i,
        Err(e) => return fail(out, 500, Reason::Load(e), 0),
    };
    let mut ctx = Ctx {
        policy,
        req,
        out: &mut out[..cap],
        out_len: 0,
        out_cap: cap,
        status: 200,
        ctype: CT_JSON,
        overflow: false,
        kv,
        clock,
    };
    let r = inst.call_handle(&mut ctx);
    let fuel_used = inst.fuel_used();
    let (status, ctype, len, overflow) = (ctx.status, ctx.ctype, ctx.out_len, ctx.overflow);
    drop(ctx);
    drop(inst);
    let reason = match r {
        Ok(0) => Reason::Ok,
        Ok(c) => Reason::ScriptExit(c),
        Err(_) if overflow => Reason::ResponseTooLarge,
        Err(t) => Reason::Trap(t),
    };
    match reason {
        Reason::Ok => Outcome { status, content_type: ctype, body_len: len, reason, fuel_used },
        Reason::ResponseTooLarge => fail(out, 502, reason, fuel_used),
        Reason::Trap(Trap::OutOfFuel) | Reason::Trap(Trap::Timeout) | Reason::Trap(Trap::HostCallLimit) => {
            fail(out, 503, reason, fuel_used)
        }
        _ => fail(out, 500, reason, fuel_used),
    }
}
