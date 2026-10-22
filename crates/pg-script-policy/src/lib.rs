//! QED Script policy (`app.policy`), host-API allowlist, platform resource ceilings and the
//! KV access-control model (LAW_015, LAW_016, LAW_021).
//!
//! `#![no_std]`, zero allocation, `#![forbid(unsafe_code)]`.
#![no_std]
#![forbid(unsafe_code)]

/// Runtime identifier a policy must name (bound into the signature, LAW_020).
pub const RUNTIME_ID: &[u8] = b"qs-wasm/1";

/// Hard platform ceilings. A signed policy can only request values at or below these (LAW_016).
pub const CEIL_MEMORY_BYTES: u32 = 1 << 20;
pub const CEIL_FUEL: u32 = 50_000_000;
pub const CEIL_STACK_DEPTH: u32 = 16;
pub const CEIL_REQUEST_BYTES: u32 = 64 * 1024;
pub const CEIL_RESPONSE_BYTES: u32 = 64 * 1024;
pub const CEIL_HOST_CALLS: u32 = 4096;
pub const CEIL_EXEC_US: u32 = 100_000;

pub const MAX_MODULE_ID: usize = 32;
pub const MAX_PREFIXES: usize = 4;
pub const MAX_PREFIX_LEN: usize = 16;
pub const MAX_KEY_LEN: usize = 32;
pub const MAX_VAL_LEN: usize = 128;
pub const MAX_POLICY_LEN: usize = 2048;

/// The complete set of host functions that exist. Anything else is unlinkable (LAW_015).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Api {
    ReqMethod = 0,
    ReqField = 1,
    RespStatus = 2,
    RespContentType = 3,
    RespWrite = 4,
    KvGet = 5,
    KvPut = 6,
    KvDelete = 7,
}

pub const ALL_APIS: [Api; 8] = [
    Api::ReqMethod,
    Api::ReqField,
    Api::RespStatus,
    Api::RespContentType,
    Api::RespWrite,
    Api::KvGet,
    Api::KvPut,
    Api::KvDelete,
];

impl Api {
    pub fn name(self) -> &'static [u8] {
        match self {
            Api::ReqMethod => b"req_method",
            Api::ReqField => b"req_field",
            Api::RespStatus => b"resp_status",
            Api::RespContentType => b"resp_content_type",
            Api::RespWrite => b"resp_write",
            Api::KvGet => b"kv_get",
            Api::KvPut => b"kv_put",
            Api::KvDelete => b"kv_delete",
        }
    }
    pub fn from_name(n: &[u8]) -> Option<Api> {
        let mut i = 0;
        while i < ALL_APIS.len() {
            if ALL_APIS[i].name() == n {
                return Some(ALL_APIS[i]);
            }
            i += 1;
        }
        None
    }
    pub fn from_id(id: u8) -> Option<Api> {
        if (id as usize) < ALL_APIS.len() {
            Some(ALL_APIS[id as usize])
        } else {
            None
        }
    }
    /// (number of i32 params, number of i32 results)
    pub fn signature(self) -> (u8, u8) {
        match self {
            Api::ReqMethod => (0, 1),
            Api::ReqField => (3, 1),
            Api::RespStatus | Api::RespContentType => (1, 0),
            Api::RespWrite => (2, 0),
            Api::KvGet | Api::KvPut => (4, 1),
            Api::KvDelete => (2, 1),
        }
    }
}

/// Resource limits enforced for one request (LAW_016).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_memory_bytes: u32,
    pub max_fuel: u32,
    pub max_stack_depth: u32,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub max_host_calls: u32,
    pub max_exec_us: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    TooLong,
    NotUtf8Ascii,
    BadLine,
    UnknownKey,
    DuplicateKey,
    MissingKey,
    BadNumber,
    ExceedsCeiling,
    ZeroLimit,
    BadRuntime,
    BadModuleId,
    UnknownApi,
    TooManyPrefixes,
    BadPrefix,
    /// `kv_get`/`kv_put`/`kv_delete` allowed without a matching prefix grant (or vice versa).
    Contradiction,
}

#[derive(Clone, Copy, Debug)]
pub struct Policy<'a> {
    pub module_id: &'a [u8],
    pub version: u32,
    pub allow: u16,
    pub limits: Limits,
    kv_read: [&'a [u8]; MAX_PREFIXES],
    n_read: usize,
    kv_write: [&'a [u8]; MAX_PREFIXES],
    n_write: usize,
}

fn valid_ident(b: &[u8], max: usize) -> bool {
    if b.is_empty() || b.len() > max {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'_' || c == b'-' || c == b'/') {
            return false;
        }
        i += 1;
    }
    true
}

fn parse_u32(b: &[u8]) -> Result<u32, PolicyError> {
    if b.is_empty() || b.len() > 10 {
        return Err(PolicyError::BadNumber);
    }
    let mut v: u64 = 0;
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            return Err(PolicyError::BadNumber);
        }
        v = v * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    if v > u32::MAX as u64 {
        return Err(PolicyError::BadNumber);
    }
    Ok(v as u32)
}

fn trim(mut b: &[u8]) -> &[u8] {
    while let [f, rest @ ..] = b {
        if *f == b' ' || *f == b'\t' || *f == b'\r' {
            b = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., l] = b {
        if *l == b' ' || *l == b'\t' || *l == b'\r' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn limit(b: &[u8], ceil: u32) -> Result<u32, PolicyError> {
    let v = parse_u32(b)?;
    if v == 0 {
        return Err(PolicyError::ZeroLimit);
    }
    if v > ceil {
        return Err(PolicyError::ExceedsCeiling);
    }
    Ok(v)
}

impl<'a> Policy<'a> {
    /// Verification-only constructor: a policy that allows exactly the APIs in `allow`, with minimal limits.
    #[cfg(kani)]
    pub fn for_proof(allow: u16) -> Policy<'static> {
        Policy {
            module_id: b"m",
            version: 1,
            allow,
            limits: Limits {
                max_memory_bytes: 1,
                max_fuel: 1,
                max_stack_depth: 1,
                max_request_bytes: 1,
                max_response_bytes: 1,
                max_host_calls: 1,
                max_exec_us: 1,
            },
            kv_read: [b""; MAX_PREFIXES],
            n_read: 0,
            kv_write: [b""; MAX_PREFIXES],
            n_write: 0,
        }
    }

    pub fn allows(&self, api: Api) -> bool {
        self.allow & (1u16 << (api as u8)) != 0
    }
    pub fn kv_read_prefixes(&self) -> &[&'a [u8]] {
        &self.kv_read[..self.n_read]
    }
    pub fn kv_write_prefixes(&self) -> &[&'a [u8]] {
        &self.kv_write[..self.n_write]
    }

    /// Strict parser: unknown or duplicate keys, out-of-ceiling limits, missing mandatory keys
    /// and allow/prefix contradictions are all rejected (LAW_015, LAW_016, LAW_020).
    pub fn parse(text: &'a [u8]) -> Result<Policy<'a>, PolicyError> {
        if text.len() > MAX_POLICY_LEN {
            return Err(PolicyError::TooLong);
        }
        let mut i = 0;
        while i < text.len() {
            let c = text[i];
            if !(c == b'\n' || c == b'\r' || c == b'\t' || (0x20..0x7f).contains(&c)) {
                return Err(PolicyError::NotUtf8Ascii);
            }
            i += 1;
        }
        let mut runtime = false;
        let mut module_id: Option<&'a [u8]> = None;
        let mut version: Option<u32> = None;
        let mut allow: u16 = 0;
        let mut lim = [None::<u32>; 7];
        let mut kv_read = [&b""[..]; MAX_PREFIXES];
        let mut n_read = 0;
        let mut kv_write = [&b""[..]; MAX_PREFIXES];
        let mut n_write = 0;

        for raw in text.split(|b| *b == b'\n') {
            let line = trim(raw);
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            let eq = match line.iter().position(|b| *b == b'=') {
                Some(p) => p,
                None => return Err(PolicyError::BadLine),
            };
            let key = trim(&line[..eq]);
            let val = trim(&line[eq + 1..]);
            match key {
                b"runtime" => {
                    if runtime {
                        return Err(PolicyError::DuplicateKey);
                    }
                    if val != RUNTIME_ID {
                        return Err(PolicyError::BadRuntime);
                    }
                    runtime = true;
                }
                b"module" => {
                    if module_id.is_some() {
                        return Err(PolicyError::DuplicateKey);
                    }
                    if !valid_ident(val, MAX_MODULE_ID) {
                        return Err(PolicyError::BadModuleId);
                    }
                    module_id = Some(val);
                }
                b"version" => {
                    if version.is_some() {
                        return Err(PolicyError::DuplicateKey);
                    }
                    version = Some(parse_u32(val)?);
                }
                b"allow" => {
                    let api = Api::from_name(val).ok_or(PolicyError::UnknownApi)?;
                    let bit = 1u16 << (api as u8);
                    if allow & bit != 0 {
                        return Err(PolicyError::DuplicateKey);
                    }
                    allow |= bit;
                }
                b"kv_read" | b"kv_write" => {
                    if !valid_ident(val, MAX_PREFIX_LEN) {
                        return Err(PolicyError::BadPrefix);
                    }
                    let (arr, n) = if key == b"kv_read" {
                        (&mut kv_read, &mut n_read)
                    } else {
                        (&mut kv_write, &mut n_write)
                    };
                    if *n >= MAX_PREFIXES {
                        return Err(PolicyError::TooManyPrefixes);
                    }
                    arr[*n] = val;
                    *n += 1;
                }
                b"max_memory_bytes" | b"max_fuel" | b"max_stack_depth" | b"max_request_bytes"
                | b"max_response_bytes" | b"max_host_calls" | b"max_exec_us" => {
                    let (idx, ceil) = match key {
                        b"max_memory_bytes" => (0, CEIL_MEMORY_BYTES),
                        b"max_fuel" => (1, CEIL_FUEL),
                        b"max_stack_depth" => (2, CEIL_STACK_DEPTH),
                        b"max_request_bytes" => (3, CEIL_REQUEST_BYTES),
                        b"max_response_bytes" => (4, CEIL_RESPONSE_BYTES),
                        b"max_host_calls" => (5, CEIL_HOST_CALLS),
                        _ => (6, CEIL_EXEC_US),
                    };
                    if lim[idx].is_some() {
                        return Err(PolicyError::DuplicateKey);
                    }
                    lim[idx] = Some(limit(val, ceil)?);
                }
                _ => return Err(PolicyError::UnknownKey),
            }
        }
        if !runtime {
            return Err(PolicyError::MissingKey);
        }
        let module_id = module_id.ok_or(PolicyError::MissingKey)?;
        let version = version.ok_or(PolicyError::MissingKey)?;
        let mut l = [0u32; 7];
        let mut j = 0;
        while j < 7 {
            l[j] = lim[j].ok_or(PolicyError::MissingKey)?;
            j += 1;
        }
        let p = Policy {
            module_id,
            version,
            allow,
            limits: Limits {
                max_memory_bytes: l[0],
                max_fuel: l[1],
                max_stack_depth: l[2],
                max_request_bytes: l[3],
                max_response_bytes: l[4],
                max_host_calls: l[5],
                max_exec_us: l[6],
            },
            kv_read,
            n_read,
            kv_write,
            n_write,
        };
        // kv_get needs a read grant; kv_put/kv_delete need a write grant; grants without APIs are errors.
        let reads = p.allows(Api::KvGet);
        let writes = p.allows(Api::KvPut) || p.allows(Api::KvDelete);
        if reads != (n_read > 0) || writes != (n_write > 0) {
            return Err(PolicyError::Contradiction);
        }
        Ok(p)
    }
}

// ---------------------------------------------------------------------------
// KV access control (LAW_021)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvOp {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvError {
    /// Request carries no authenticated principal (id 0 = anonymous).
    Unauthenticated,
    /// Key malformed or outside the policy's granted prefixes.
    Denied,
    NotFound,
    Full,
    ValueTooLong,
}

pub const NS_KEY_LEN: usize = 4 + MAX_MODULE_ID + 1 + MAX_KEY_LEN;

/// Pure authorization decision. The caller (trusted host glue) supplies `principal` from the
/// authentication context; the script never names a principal or namespace (LAW_021).
pub fn kv_authorize(policy: &Policy<'_>, principal: u32, op: KvOp, key: &[u8]) -> Result<(), KvError> {
    if principal == 0 {
        return Err(KvError::Unauthenticated);
    }
    if key.is_empty() || key.len() > MAX_KEY_LEN || !valid_ident(key, MAX_KEY_LEN) {
        return Err(KvError::Denied);
    }
    let prefixes = match op {
        KvOp::Read => policy.kv_read_prefixes(),
        KvOp::Write => policy.kv_write_prefixes(),
    };
    let mut i = 0;
    while i < prefixes.len() {
        if key.starts_with(prefixes[i]) {
            return Ok(());
        }
        i += 1;
    }
    Err(KvError::Denied)
}

/// Build the storage key `principal(4 BE) || module_id || 0x00 || key`. Distinct (principal, module, key)
/// triples always yield distinct storage keys because module ids and keys contain no 0x00 byte and
/// the principal has a fixed width.
pub fn namespaced_key(principal: u32, module_id: &[u8], key: &[u8], out: &mut [u8; NS_KEY_LEN]) -> usize {
    let mut n = 0;
    let p = principal.to_be_bytes();
    let mut i = 0;
    while i < 4 {
        out[n] = p[i];
        n += 1;
        i += 1;
    }
    i = 0;
    while i < module_id.len() {
        out[n] = module_id[i];
        n += 1;
        i += 1;
    }
    out[n] = 0;
    n += 1;
    i = 0;
    while i < key.len() {
        out[n] = key[i];
        n += 1;
        i += 1;
    }
    n
}

pub const KV_SLOTS: usize = 32;
/// Per-(principal, module) namespace quota so one script cannot starve the others (LAW_016/021).
pub const KV_NS_QUOTA: usize = 8;

#[derive(Clone, Copy)]
struct Slot {
    used: bool,
    klen: u8,
    vlen: u8,
    key: [u8; NS_KEY_LEN],
    val: [u8; MAX_VAL_LEN],
}

const EMPTY_SLOT: Slot = Slot { used: false, klen: 0, vlen: 0, key: [0; NS_KEY_LEN], val: [0; MAX_VAL_LEN] };

/// In-memory KV store (the Storage PD's state). Not persistent, not encrypted (next stage).
pub struct Kv {
    slots: [Slot; KV_SLOTS],
}

impl Default for Kv {
    fn default() -> Self {
        Self::new()
    }
}

impl Kv {
    pub const fn new() -> Self {
        Kv { slots: [EMPTY_SLOT; KV_SLOTS] }
    }

    fn find(&self, k: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < KV_SLOTS {
            let s = &self.slots[i];
            if s.used && &s.key[..s.klen as usize] == k {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn ns_count(&self, ns_prefix: &[u8]) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < KV_SLOTS {
            let s = &self.slots[i];
            if s.used && s.key[..s.klen as usize].starts_with(ns_prefix) {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Returns the value length (copies `min(len, out.len())`).
    pub fn get(&self, policy: &Policy<'_>, principal: u32, key: &[u8], out: &mut [u8]) -> Result<usize, KvError> {
        kv_authorize(policy, principal, KvOp::Read, key)?;
        let mut nk = [0u8; NS_KEY_LEN];
        let n = namespaced_key(principal, policy.module_id, key, &mut nk);
        let i = self.find(&nk[..n]).ok_or(KvError::NotFound)?;
        let s = &self.slots[i];
        let vl = s.vlen as usize;
        let c = if vl < out.len() { vl } else { out.len() };
        out[..c].copy_from_slice(&s.val[..c]);
        Ok(vl)
    }

    pub fn put(&mut self, policy: &Policy<'_>, principal: u32, key: &[u8], val: &[u8]) -> Result<(), KvError> {
        kv_authorize(policy, principal, KvOp::Write, key)?;
        if val.len() > MAX_VAL_LEN {
            return Err(KvError::ValueTooLong);
        }
        let mut nk = [0u8; NS_KEY_LEN];
        let n = namespaced_key(principal, policy.module_id, key, &mut nk);
        let idx = match self.find(&nk[..n]) {
            Some(i) => i,
            None => {
                let ns_len = 4 + policy.module_id.len() + 1;
                if self.ns_count(&nk[..ns_len]) >= KV_NS_QUOTA {
                    return Err(KvError::Full);
                }
                let mut free = None;
                let mut i = 0;
                while i < KV_SLOTS {
                    if !self.slots[i].used {
                        free = Some(i);
                        break;
                    }
                    i += 1;
                }
                free.ok_or(KvError::Full)?
            }
        };
        let s = &mut self.slots[idx];
        *s = EMPTY_SLOT;
        s.used = true;
        s.klen = n as u8;
        s.key[..n].copy_from_slice(&nk[..n]);
        s.vlen = val.len() as u8;
        s.val[..val.len()].copy_from_slice(val);
        Ok(())
    }

    pub fn delete(&mut self, policy: &Policy<'_>, principal: u32, key: &[u8]) -> Result<(), KvError> {
        kv_authorize(policy, principal, KvOp::Write, key)?;
        let mut nk = [0u8; NS_KEY_LEN];
        let n = namespaced_key(principal, policy.module_id, key, &mut nk);
        let i = self.find(&nk[..n]).ok_or(KvError::NotFound)?;
        self.slots[i] = EMPTY_SLOT;
        Ok(())
    }
}

pub mod route;

#[cfg(test)]
mod tests;
#[cfg(kani)]
mod proofs;
