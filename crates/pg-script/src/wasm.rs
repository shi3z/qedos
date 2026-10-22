//! WebAssembly MVP subset: i32 values only, one linear memory (no `memory.grow`), no tables,
//! globals, start function, floats, SIMD, threads, bulk memory or multi-value.
//!
//! Accepted binary sections: type(1), import(2), function(3), memory(5), export(7), code(10),
//! data(11), plus ignored custom(0). Everything else is rejected at load time.

use pg_script_policy::Limits;

pub const PAGE: usize = 65536;
pub const MAX_TYPES: usize = 16;
pub const MAX_PARAMS: usize = 4;
pub const MAX_IMPORTS: usize = 16;
pub const MAX_FUNCS: usize = 32;
pub const MAX_DATA: usize = 8;
pub const MAX_LOCALS: usize = 16;
pub const MAX_NEST: usize = 16;
pub const MAX_CALL_DEPTH: usize = 16;
pub const VALUE_STACK: usize = 1024;
pub const CTRL_STACK: usize = MAX_NEST * MAX_CALL_DEPTH;
pub const CLOCK_INTERVAL: u32 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    BadMagic,
    Truncated,
    BadLeb,
    UnsupportedSection,
    SectionOrder,
    TooMany,
    UnsupportedType,
    UnsupportedImport,
    UnsupportedOpcode,
    BadFunction,
    BadControl,
    BadIndex,
    BadMemory,
    MemoryTooLarge,
    BadData,
    NoHandle,
    UnresolvedImport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trap {
    Unreachable,
    OutOfBounds,
    DivByZero,
    IntOverflow,
    OutOfFuel,
    ValueStackOverflow,
    CallDepth,
    HostCallLimit,
    Timeout,
    /// Host function refused the call (policy/ACL denial or bad argument).
    HostDenied,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FuncType {
    pub n_params: u8,
    pub n_results: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct Import<'a> {
    pub module: &'a [u8],
    pub name: &'a [u8],
    pub ty: FuncType,
}

#[derive(Clone, Copy, Debug)]
struct FuncDef<'a> {
    ty: FuncType,
    n_locals: u8, // params + declared locals
    code: &'a [u8], // instruction bytes, ends with 0x0B
}

#[derive(Clone, Copy, Debug)]
struct DataSeg<'a> {
    offset: u32,
    bytes: &'a [u8],
}

/// A parsed *and fully validated* module. Fields are private: the only constructor is [`Module::parse`].
#[derive(Clone, Debug)]
pub struct Module<'a> {
    imports: [Import<'a>; MAX_IMPORTS],
    n_imports: usize,
    funcs: [FuncDef<'a>; MAX_FUNCS],
    n_funcs: usize,
    mem_pages: u32,
    has_memory: bool,
    data: [DataSeg<'a>; MAX_DATA],
    n_data: usize,
    handle: usize, // function-index-space index of export "handle"
}

// ---------------------------------------------------------------------------
// Reader

struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn eof(&self) -> bool {
        self.p >= self.b.len()
    }
    fn u8(&mut self) -> Result<u8, LoadError> {
        let v = *self.b.get(self.p).ok_or(LoadError::Truncated)?;
        self.p += 1;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32, LoadError> {
        let (v, np) = leb_u32(self.b, self.p).ok_or(LoadError::BadLeb)?;
        self.p = np;
        Ok(v)
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], LoadError> {
        let end = self.p.checked_add(n).ok_or(LoadError::Truncated)?;
        let s = self.b.get(self.p..end).ok_or(LoadError::Truncated)?;
        self.p = end;
        Ok(s)
    }
}

/// Canonical LEB128 u32 (max 5 bytes, unused bits of last byte must be zero).
pub fn leb_u32(b: &[u8], mut p: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(p)?;
        p += 1;
        if shift == 28 && byte & 0x70 != 0 {
            return None;
        }
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some((result, p));
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
}

/// LEB128 s32 (max 5 bytes; high bits of last byte must be a sign extension).
pub fn leb_i32(b: &[u8], mut p: usize) -> Option<(i32, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(p)?;
        p += 1;
        if shift == 28 {
            // remaining 4 bits (bits 28..31) plus 3 bits that must be sign-extension of bit 3.
            let sign = (byte >> 3) & 1;
            let hi = (byte >> 4) & 0x7;
            if byte & 0x80 != 0 || (sign == 0 && hi != 0) || (sign == 1 && hi != 0x7) {
                return None;
            }
            result |= ((byte & 0x7f) as i64) << shift;
            // sign-extend from 32 bits
            return Some((result as u32 as i32, p));
        }
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if byte & 0x40 != 0 {
                result |= -1i64 << shift;
            }
            return Some((result as i32, p));
        }
    }
}

// ---------------------------------------------------------------------------
// Opcodes (the complete accepted set)

mod op {
    pub const UNREACHABLE: u8 = 0x00;
    pub const NOP: u8 = 0x01;
    pub const BLOCK: u8 = 0x02;
    pub const LOOP: u8 = 0x03;
    pub const IF: u8 = 0x04;
    pub const ELSE: u8 = 0x05;
    pub const END: u8 = 0x0B;
    pub const BR: u8 = 0x0C;
    pub const BR_IF: u8 = 0x0D;
    pub const RETURN: u8 = 0x0F;
    pub const CALL: u8 = 0x10;
    pub const DROP: u8 = 0x1A;
    pub const SELECT: u8 = 0x1B;
    pub const LOCAL_GET: u8 = 0x20;
    pub const LOCAL_SET: u8 = 0x21;
    pub const LOCAL_TEE: u8 = 0x22;
    pub const I32_LOAD: u8 = 0x28;
    pub const I32_LOAD8_S: u8 = 0x2C;
    pub const I32_LOAD8_U: u8 = 0x2D;
    pub const I32_LOAD16_S: u8 = 0x2E;
    pub const I32_LOAD16_U: u8 = 0x2F;
    pub const I32_STORE: u8 = 0x36;
    pub const I32_STORE8: u8 = 0x3A;
    pub const I32_STORE16: u8 = 0x3B;
    pub const MEMORY_SIZE: u8 = 0x3F;
    pub const I32_CONST: u8 = 0x41;
    pub const I32_EQZ: u8 = 0x45;
    pub const I32_GE_U: u8 = 0x4F;
    pub const I32_ADD: u8 = 0x6A;
    pub const I32_SHR_U: u8 = 0x76;
}

fn is_numeric(o: u8) -> bool {
    (op::I32_EQZ..=op::I32_GE_U).contains(&o) || (op::I32_ADD..=op::I32_SHR_U).contains(&o)
}
fn is_load(o: u8) -> bool {
    matches!(o, op::I32_LOAD | op::I32_LOAD8_S | op::I32_LOAD8_U | op::I32_LOAD16_S | op::I32_LOAD16_U)
}
fn is_store(o: u8) -> bool {
    matches!(o, op::I32_STORE | op::I32_STORE8 | op::I32_STORE16)
}
fn access_size(o: u8) -> u32 {
    match o {
        op::I32_LOAD | op::I32_STORE => 4,
        op::I32_LOAD16_S | op::I32_LOAD16_U | op::I32_STORE16 => 2,
        _ => 1,
    }
}

/// Skip the immediates of `o` (whose opcode byte has already been consumed); returns new pc.
/// `Err` on truncation/non-canonical LEB. Also rejects every opcode outside the accepted set.
fn skip_imm(code: &[u8], pc: usize, o: u8) -> Result<usize, LoadError> {
    match o {
        op::UNREACHABLE | op::NOP | op::ELSE | op::END | op::RETURN | op::DROP | op::SELECT => Ok(pc),
        op::BLOCK | op::LOOP | op::IF => match code.get(pc) {
            Some(0x40) | Some(0x7F) => Ok(pc + 1),
            Some(_) => Err(LoadError::UnsupportedType),
            None => Err(LoadError::Truncated),
        },
        op::BR | op::BR_IF | op::CALL | op::LOCAL_GET | op::LOCAL_SET | op::LOCAL_TEE => {
            leb_u32(code, pc).map(|(_, p)| p).ok_or(LoadError::BadLeb)
        }
        op::I32_CONST => leb_i32(code, pc).map(|(_, p)| p).ok_or(LoadError::BadLeb),
        op::MEMORY_SIZE => match code.get(pc) {
            Some(0x00) => Ok(pc + 1),
            _ => Err(LoadError::BadMemory),
        },
        _ if is_load(o) || is_store(o) => {
            let (_, p) = leb_u32(code, pc).ok_or(LoadError::BadLeb)?;
            let (_, p) = leb_u32(code, p).ok_or(LoadError::BadLeb)?;
            Ok(p)
        }
        _ if is_numeric(o) => Ok(pc),
        _ => Err(LoadError::UnsupportedOpcode),
    }
}

impl<'a> Module<'a> {
    pub fn imports(&self) -> &[Import<'a>] {
        &self.imports[..self.n_imports]
    }
    pub fn memory_bytes(&self) -> usize {
        self.mem_pages as usize * PAGE
    }

    /// Parse and validate. Every function body is checked here (opcode whitelist, structured
    /// control nesting, local/call/branch indices, memory presence) so the interpreter never has to
    /// trust the binary.
    pub fn parse(wasm: &'a [u8]) -> Result<Module<'a>, LoadError> {
        if wasm.len() < 8 || wasm[..8] != [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00] {
            return Err(LoadError::BadMagic);
        }
        let mut r = Rd { b: wasm, p: 8 };
        let mut types = [FuncType::default(); MAX_TYPES];
        let mut n_types = 0usize;
        let mut imports = [Import { module: &[], name: &[], ty: FuncType::default() }; MAX_IMPORTS];
        let mut n_imports = 0usize;
        let mut func_types = [0u8; MAX_FUNCS];
        let mut n_funcs = 0usize;
        let mut mem_pages = 0u32;
        let mut has_memory = false;
        let mut handle: Option<u32> = None;
        let empty = FuncDef { ty: FuncType::default(), n_locals: 0, code: &[] };
        let mut funcs = [empty; MAX_FUNCS];
        let mut n_code = 0usize;
        let mut data = [DataSeg { offset: 0, bytes: &[] }; MAX_DATA];
        let mut n_data = 0usize;
        let mut last_id = 0u8;
        let mut export_raw: Option<&'a [u8]> = None;
        let mut data_raw: Option<&'a [u8]> = None;

        while !r.eof() {
            let id = r.u8()?;
            let size = r.u32()? as usize;
            let body = r.bytes(size)?;
            if id == 0 {
                continue;
            }
            let rank = match id {
                1 => 1,
                2 => 2,
                3 => 3,
                5 => 4,
                7 => 5,
                10 => 6,
                11 => 7,
                _ => return Err(LoadError::UnsupportedSection),
            };
            if rank <= last_id {
                return Err(LoadError::SectionOrder);
            }
            last_id = rank;
            let mut s = Rd { b: body, p: 0 };
            match id {
                1 => {
                    let n = s.u32()? as usize;
                    if n > MAX_TYPES {
                        return Err(LoadError::TooMany);
                    }
                    while n_types < n {
                        if s.u8()? != 0x60 {
                            return Err(LoadError::UnsupportedType);
                        }
                        let np = s.u32()? as usize;
                        if np > MAX_PARAMS {
                            return Err(LoadError::UnsupportedType);
                        }
                        let mut i = 0;
                        while i < np {
                            if s.u8()? != 0x7F {
                                return Err(LoadError::UnsupportedType);
                            }
                            i += 1;
                        }
                        let nr = s.u32()? as usize;
                        if nr > 1 {
                            return Err(LoadError::UnsupportedType);
                        }
                        if nr == 1 && s.u8()? != 0x7F {
                            return Err(LoadError::UnsupportedType);
                        }
                        types[n_types] = FuncType { n_params: np as u8, n_results: nr as u8 };
                        n_types += 1;
                    }
                }
                2 => {
                    let n = s.u32()? as usize;
                    if n > MAX_IMPORTS {
                        return Err(LoadError::TooMany);
                    }
                    while n_imports < n {
                        let ml = s.u32()? as usize;
                        let module = s.bytes(ml)?;
                        let nl = s.u32()? as usize;
                        let name = s.bytes(nl)?;
                        if s.u8()? != 0x00 {
                            return Err(LoadError::UnsupportedImport); // only function imports
                        }
                        let t = s.u32()? as usize;
                        if t >= n_types {
                            return Err(LoadError::BadIndex);
                        }
                        imports[n_imports] = Import { module, name, ty: types[t] };
                        n_imports += 1;
                    }
                }
                3 => {
                    let n = s.u32()? as usize;
                    if n > MAX_FUNCS {
                        return Err(LoadError::TooMany);
                    }
                    while n_funcs < n {
                        let t = s.u32()? as usize;
                        if t >= n_types {
                            return Err(LoadError::BadIndex);
                        }
                        func_types[n_funcs] = t as u8;
                        n_funcs += 1;
                    }
                }
                5 => {
                    if s.u32()? != 1 {
                        return Err(LoadError::BadMemory);
                    }
                    let flag = s.u8()?;
                    let min = s.u32()?;
                    if flag == 1 {
                        let max = s.u32()?;
                        if max < min {
                            return Err(LoadError::BadMemory);
                        }
                    } else if flag != 0 {
                        return Err(LoadError::BadMemory); // shared memory (threads) rejected
                    }
                    if min > 16 {
                        return Err(LoadError::MemoryTooLarge);
                    }
                    mem_pages = min;
                    has_memory = true;
                }
                7 => export_raw = Some(body),
                10 => {
                    let n = s.u32()? as usize;
                    if n != n_funcs {
                        return Err(LoadError::BadFunction);
                    }
                    while n_code < n {
                        let sz = s.u32()? as usize;
                        let fb = s.bytes(sz)?;
                        let mut f = Rd { b: fb, p: 0 };
                        let ngroups = f.u32()? as usize;
                        let ty = types[func_types[n_code] as usize];
                        let mut total = ty.n_params as usize;
                        let mut g = 0;
                        while g < ngroups {
                            let cnt = f.u32()? as usize;
                            if f.u8()? != 0x7F {
                                return Err(LoadError::UnsupportedType);
                            }
                            total = total.checked_add(cnt).ok_or(LoadError::TooMany)?;
                            if total > MAX_LOCALS {
                                return Err(LoadError::TooMany);
                            }
                            g += 1;
                        }
                        funcs[n_code] = FuncDef { ty, n_locals: total as u8, code: &fb[f.p..] };
                        n_code += 1;
                    }
                }
                11 => data_raw = Some(body),
                _ => return Err(LoadError::UnsupportedSection),
            }
            if !s.eof() && id != 7 && id != 11 {
                return Err(LoadError::BadFunction);
            }
        }
        if n_code != n_funcs {
            return Err(LoadError::BadFunction);
        }
        // exports: exactly find "handle" func export
        if let Some(raw) = export_raw {
            let mut s = Rd { b: raw, p: 0 };
            let n = s.u32()?;
            let mut i = 0;
            while i < n {
                let nl = s.u32()? as usize;
                let name = s.bytes(nl)?;
                let kind = s.u8()?;
                let idx = s.u32()?;
                if kind == 0x00 && name == b"handle" {
                    handle = Some(idx);
                }
                i += 1;
            }
            if !s.eof() {
                return Err(LoadError::BadFunction);
            }
        }
        let handle = handle.ok_or(LoadError::NoHandle)? as usize;
        if handle < n_imports || handle - n_imports >= n_funcs {
            return Err(LoadError::NoHandle);
        }
        let hty = funcs[handle - n_imports].ty;
        if hty.n_params != 0 || hty.n_results != 1 {
            return Err(LoadError::NoHandle);
        }
        // data segments (active, `i32.const off; end`)
        if let Some(raw) = data_raw {
            let mut s = Rd { b: raw, p: 0 };
            let n = s.u32()? as usize;
            if n > MAX_DATA {
                return Err(LoadError::TooMany);
            }
            while n_data < n {
                if s.u32()? != 0 || !has_memory {
                    return Err(LoadError::BadData);
                }
                if s.u8()? != op::I32_CONST {
                    return Err(LoadError::BadData);
                }
                let (off, np) = leb_i32(s.b, s.p).ok_or(LoadError::BadLeb)?;
                s.p = np;
                if s.u8()? != op::END || off < 0 {
                    return Err(LoadError::BadData);
                }
                let len = s.u32()? as usize;
                let bytes = s.bytes(len)?;
                let end = (off as u64) + (len as u64);
                if end > (mem_pages as u64) * (PAGE as u64) {
                    return Err(LoadError::BadData);
                }
                data[n_data] = DataSeg { offset: off as u32, bytes };
                n_data += 1;
            }
            if !s.eof() {
                return Err(LoadError::BadData);
            }
        }
        let m = Module {
            imports,
            n_imports,
            funcs,
            n_funcs,
            mem_pages,
            has_memory,
            data,
            n_data,
            handle,
        };
        let mut i = 0;
        while i < n_funcs {
            m.validate_body(i)?;
            i += 1;
        }
        Ok(m)
    }

    fn validate_body(&self, fi: usize) -> Result<(), LoadError> {
        let f = &self.funcs[fi];
        let code = f.code;
        let total_funcs = self.n_imports + self.n_funcs;
        let mut pc = 0usize;
        let mut depth = 0usize; // open blocks inside the function (function body itself = level 0)
        let mut else_seen = [false; MAX_NEST + 1];
        let mut is_if = [false; MAX_NEST + 1];
        loop {
            let o = *code.get(pc).ok_or(LoadError::BadControl)?;
            let np = skip_imm(code, pc + 1, o)?;
            match o {
                op::BLOCK | op::LOOP | op::IF => {
                    if depth >= MAX_NEST {
                        return Err(LoadError::TooMany);
                    }
                    depth += 1;
                    else_seen[depth] = false;
                    is_if[depth] = o == op::IF;
                }
                op::ELSE => {
                    if depth == 0 || !is_if[depth] || else_seen[depth] {
                        return Err(LoadError::BadControl);
                    }
                    else_seen[depth] = true;
                }
                op::END => {
                    if depth == 0 {
                        if np != code.len() {
                            return Err(LoadError::BadControl);
                        }
                        return Ok(());
                    }
                    depth -= 1;
                }
                op::BR | op::BR_IF => {
                    let (d, _) = leb_u32(code, pc + 1).ok_or(LoadError::BadLeb)?;
                    if d as usize > depth {
                        return Err(LoadError::BadIndex);
                    }
                }
                op::CALL => {
                    let (d, _) = leb_u32(code, pc + 1).ok_or(LoadError::BadLeb)?;
                    if d as usize >= total_funcs {
                        return Err(LoadError::BadIndex);
                    }
                }
                op::LOCAL_GET | op::LOCAL_SET | op::LOCAL_TEE => {
                    let (d, _) = leb_u32(code, pc + 1).ok_or(LoadError::BadLeb)?;
                    if d >= f.n_locals as u32 {
                        return Err(LoadError::BadIndex);
                    }
                }
                _ if is_load(o) || is_store(o) || o == op::MEMORY_SIZE => {
                    if !self.has_memory {
                        return Err(LoadError::BadMemory);
                    }
                }
                _ => {}
            }
            pc = np;
        }
    }
}

// ---------------------------------------------------------------------------
// Memory

/// Bounds-checked linear memory view. All guest and host accesses go through [`Memory::range`].
pub struct Memory<'m> {
    pub(crate) bytes: &'m mut [u8],
}

/// Effective-address check used by every guest memory access (LAW_013).
/// Returns the start index iff `[base+offset, base+offset+size)` lies within `len`.
/// Computed in 64 bits so the sum of three u32 values cannot wrap.
#[inline]
pub fn checked_range(len: usize, base: u32, offset: u32, size: u32) -> Option<usize> {
    let start = base as u64 + offset as u64;
    let end = start + size as u64;
    if end <= len as u64 {
        Some(start as usize)
    } else {
        None
    }
}

impl<'m> Memory<'m> {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// Range `[ptr, ptr+len)` for host functions; `ptr`/`len` are guest i32s interpreted as u32.
    pub fn range(&self, ptr: i32, len: i32) -> Result<core::ops::Range<usize>, Trap> {
        let s = checked_range(self.bytes.len(), ptr as u32, 0, len as u32).ok_or(Trap::OutOfBounds)?;
        Ok(s..s + len as u32 as usize)
    }
    pub fn slice(&self, ptr: i32, len: i32) -> Result<&[u8], Trap> {
        let r = self.range(ptr, len)?;
        Ok(&self.bytes[r])
    }
    pub fn slice_mut(&mut self, ptr: i32, len: i32) -> Result<&mut [u8], Trap> {
        let r = self.range(ptr, len)?;
        Ok(&mut self.bytes[r])
    }
    pub(crate) fn load(&self, base: u32, offset: u32, size: u32) -> Result<u32, Trap> {
        let s = checked_range(self.bytes.len(), base, offset, size).ok_or(Trap::OutOfBounds)?;
        let mut v = 0u32;
        let mut i = 0usize;
        while i < size as usize {
            v |= (self.bytes[s + i] as u32) << (8 * i);
            i += 1;
        }
        Ok(v)
    }
    pub(crate) fn store(&mut self, base: u32, offset: u32, size: u32, val: u32) -> Result<(), Trap> {
        let s = checked_range(self.bytes.len(), base, offset, size).ok_or(Trap::OutOfBounds)?;
        let mut i = 0usize;
        while i < size as usize {
            self.bytes[s + i] = (val >> (8 * i)) as u8;
            i += 1;
        }
        Ok(())
    }
}

/// Host side of the import interface. `id` is the value the *linker* assigned at load time; the guest
/// can only reach ids that the resolver returned for its declared imports (LAW_015).
pub trait Host {
    fn call(&mut self, id: u8, args: &[i32], mem: &mut Memory<'_>) -> Result<Option<i32>, Trap>;
    /// Monotonic microseconds since the start of this request (LAW_017). Polled every
    /// [`CLOCK_INTERVAL`] instructions and at each host call.
    fn elapsed_us(&mut self) -> u64 {
        0
    }
}

#[derive(Clone, Copy)]
struct Ctrl {
    is_loop: bool,
    arity: u8,
    height: u32,
    cont: u32,
}

#[derive(Clone, Copy)]
struct Frame {
    func: u8,
    pc: u32,
    locals: u32,
    ctrl_base: u32,
}

/// One execution instance. Created per request; memory is zeroed on creation and scrubbed on drop
/// (LAW_019).
pub struct Instance<'a, 'm> {
    module: &'a Module<'a>,
    mem: Memory<'m>,
    link: [u8; MAX_IMPORTS],
    limits: Limits,
    fuel: u64,
    host_calls: u32,
    vals: [i32; VALUE_STACK],
    sp: usize,
    ctrls: [Ctrl; CTRL_STACK],
    cp: usize,
    frames: [Frame; MAX_CALL_DEPTH],
    nframes: usize,
}

impl<'a, 'm> Drop for Instance<'a, 'm> {
    fn drop(&mut self) {
        let mut i = 0;
        while i < self.mem.bytes.len() {
            self.mem.bytes[i] = 0;
            i += 1;
        }
    }
}

impl<'a, 'm> Instance<'a, 'm> {
    /// Link imports through `resolve(module, name, type) -> host id`; any unresolved import fails the load.
    pub fn new<R>(
        module: &'a Module<'a>,
        mem: &'m mut [u8],
        limits: Limits,
        resolve: R,
    ) -> Result<Self, LoadError>
    where
        R: Fn(&[u8], &[u8], FuncType) -> Option<u8>,
    {
        let size = module.memory_bytes();
        if size > limits.max_memory_bytes as usize || size > mem.len() {
            return Err(LoadError::MemoryTooLarge);
        }
        let mut link = [0u8; MAX_IMPORTS];
        let mut i = 0;
        while i < module.n_imports {
            let im = &module.imports[i];
            link[i] = resolve(im.module, im.name, im.ty).ok_or(LoadError::UnresolvedImport)?;
            i += 1;
        }
        let mem = &mut mem[..size];
        let mut k = 0;
        while k < size {
            mem[k] = 0;
            k += 1;
        }
        let mut d = 0;
        while d < module.n_data {
            let seg = &module.data[d];
            let o = seg.offset as usize;
            mem[o..o + seg.bytes.len()].copy_from_slice(seg.bytes);
            d += 1;
        }
        Ok(Instance {
            module,
            mem: Memory { bytes: mem },
            link,
            limits,
            fuel: limits.max_fuel as u64,
            host_calls: 0,
            vals: [0; VALUE_STACK],
            sp: 0,
            ctrls: [Ctrl { is_loop: false, arity: 0, height: 0, cont: 0 }; CTRL_STACK],
            cp: 0,
            frames: [Frame { func: 0, pc: 0, locals: 0, ctrl_base: 0 }; MAX_CALL_DEPTH],
            nframes: 0,
        })
    }

    pub fn fuel_used(&self) -> u64 {
        self.limits.max_fuel as u64 - self.fuel
    }
    pub fn memory(&self) -> &[u8] {
        self.mem.bytes
    }

    #[inline]
    fn push(&mut self, v: i32) -> Result<(), Trap> {
        if self.sp >= VALUE_STACK {
            return Err(Trap::ValueStackOverflow);
        }
        self.vals[self.sp] = v;
        self.sp += 1;
        Ok(())
    }
    #[inline]
    fn pop(&mut self, floor: usize) -> Result<i32, Trap> {
        if self.sp <= floor {
            return Err(Trap::Malformed);
        }
        self.sp -= 1;
        Ok(self.vals[self.sp])
    }
    #[inline]
    fn burn(&mut self, n: u64) -> Result<(), Trap> {
        if self.fuel < n {
            self.fuel = 0;
            return Err(Trap::OutOfFuel);
        }
        self.fuel -= n;
        Ok(())
    }

    fn enter(&mut self, func: usize) -> Result<(), Trap> {
        let m = self.module;
        let def = &m.funcs[func];
        let depth_cap = core::cmp::min(self.limits.max_stack_depth as usize, MAX_CALL_DEPTH);
        if self.nframes >= depth_cap {
            return Err(Trap::CallDepth);
        }
        let np = def.ty.n_params as usize;
        if self.sp < np {
            return Err(Trap::Malformed);
        }
        let base = self.sp - np;
        let extra = def.n_locals as usize - np;
        if self.sp + extra > VALUE_STACK {
            return Err(Trap::ValueStackOverflow);
        }
        let mut i = 0;
        while i < extra {
            self.vals[self.sp + i] = 0;
            i += 1;
        }
        self.sp += extra;
        self.frames[self.nframes] = Frame { func: func as u8, pc: 0, locals: base as u32, ctrl_base: self.cp as u32 };
        self.nframes += 1;
        Ok(())
    }

    /// Find matching `else`/`end` for a block whose blocktype byte ends at `pc`. Returns
    /// (pc after else if any, pc after end, instructions scanned).
    fn scan(code: &[u8], mut pc: usize) -> Result<(Option<usize>, usize, u64), Trap> {
        let mut depth = 1u32;
        let mut els = None;
        let mut steps = 0u64;
        loop {
            let o = *code.get(pc).ok_or(Trap::Malformed)?;
            pc = skip_imm(code, pc + 1, o).map_err(|_| Trap::Malformed)?;
            steps += 1;
            match o {
                op::BLOCK | op::LOOP | op::IF => depth += 1,
                op::ELSE if depth == 1 => els = Some(pc),
                op::END => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok((els, pc, steps));
                    }
                }
                _ => {}
            }
        }
    }

    /// Call the exported `handle() -> i32`.
    pub fn call_handle<H: Host>(&mut self, host: &mut H) -> Result<i32, Trap> {
        self.sp = 0;
        self.cp = 0;
        self.nframes = 0;
        let h = self.module.handle - self.module.n_imports;
        self.enter(h)?;
        self.run(host)?;
        if self.sp != 1 {
            return Err(Trap::Malformed);
        }
        Ok(self.vals[0])
    }

    fn run<H: Host>(&mut self, host: &mut H) -> Result<(), Trap> {
        let m = self.module;
        let mut since_clock = 0u32;
        'frames: loop {
            let fr = self.frames[self.nframes - 1];
            let fi = fr.func as usize;
            let code = m.funcs[fi].code;
            let ty = m.funcs[fi].ty;
            let locals = fr.locals as usize;
            let floor = locals + m.funcs[fi].n_locals as usize; // operand floor of this frame
            let ctrl_base = fr.ctrl_base as usize;
            let mut pc = fr.pc as usize;
            macro_rules! do_return {
                () => {{
                    let r = if ty.n_results == 1 { Some(self.pop(floor)?) } else { None };
                    self.sp = locals;
                    self.cp = ctrl_base;
                    if let Some(v) = r {
                        self.push(v)?;
                    }
                    self.nframes -= 1;
                    if self.nframes == 0 {
                        return Ok(());
                    }
                    continue 'frames;
                }};
            }
            loop {
                self.burn(1)?;
                since_clock += 1;
                if since_clock >= CLOCK_INTERVAL {
                    since_clock = 0;
                    if host.elapsed_us() > self.limits.max_exec_us as u64 {
                        return Err(Trap::Timeout);
                    }
                }
                let o = *code.get(pc).ok_or(Trap::Malformed)?;
                let npc = skip_imm(code, pc + 1, o).map_err(|_| Trap::Malformed)?;
                match o {
                    op::UNREACHABLE => return Err(Trap::Unreachable),
                    op::NOP => pc = npc,
                    op::BLOCK | op::LOOP | op::IF => {
                        let arity = if code[pc + 1] == 0x7F { 1 } else { 0 };
                        let (els, end, steps) = Self::scan(code, npc)?;
                        self.burn(steps)?;
                        let mut cond = true;
                        if o == op::IF {
                            cond = self.pop(floor)? != 0;
                        }
                        if o == op::IF && !cond {
                            match els {
                                Some(e) => {
                                    self.push_ctrl(false, arity, end, floor)?;
                                    pc = e;
                                }
                                None => pc = end,
                            }
                        } else {
                            if self.cp - ctrl_base >= MAX_NEST || self.cp >= CTRL_STACK {
                                return Err(Trap::CallDepth);
                            }
                            self.ctrls[self.cp] = Ctrl {
                                is_loop: o == op::LOOP,
                                arity: if o == op::LOOP { 0 } else { arity },
                                height: self.sp as u32,
                                cont: if o == op::LOOP { npc as u32 } else { end as u32 },
                            };
                            self.cp += 1;
                            pc = npc;
                        }
                    }
                    op::ELSE => {
                        // reached end of then-branch: jump to after matching end
                        if self.cp <= ctrl_base {
                            return Err(Trap::Malformed);
                        }
                        self.cp -= 1;
                        pc = self.ctrls[self.cp].cont as usize;
                    }
                    op::END => {
                        if self.cp > ctrl_base {
                            self.cp -= 1;
                            pc = npc;
                        } else {
                            do_return!();
                        }
                    }
                    op::BR | op::BR_IF => {
                        let (d, _) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                        let take = if o == op::BR_IF { self.pop(floor)? != 0 } else { true };
                        if !take {
                            pc = npc;
                        } else {
                            let open = self.cp - ctrl_base;
                            if d as usize == open {
                                do_return!();
                            }
                            if d as usize > open {
                                return Err(Trap::Malformed);
                            }
                            let ti = self.cp - 1 - d as usize;
                            let c = self.ctrls[ti];
                            let keep = if c.arity == 1 { Some(self.pop(floor)?) } else { None };
                            if (c.height as usize) > self.sp {
                                return Err(Trap::Malformed);
                            }
                            self.sp = c.height as usize;
                            if let Some(v) = keep {
                                self.push(v)?;
                            }
                            if c.is_loop {
                                self.cp = ti + 1;
                            } else {
                                self.cp = ti;
                            }
                            pc = c.cont as usize;
                        }
                    }
                    op::RETURN => do_return!(),
                    op::CALL => {
                        let (idx, _) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                        let idx = idx as usize;
                        if idx < m.n_imports {
                            self.host_calls += 1;
                            if self.host_calls > self.limits.max_host_calls {
                                return Err(Trap::HostCallLimit);
                            }
                            if host.elapsed_us() > self.limits.max_exec_us as u64 {
                                return Err(Trap::Timeout);
                            }
                            let ity = m.imports[idx].ty;
                            let np = ity.n_params as usize;
                            if self.sp < floor + np {
                                return Err(Trap::Malformed);
                            }
                            let mut args = [0i32; MAX_PARAMS];
                            args[..np].copy_from_slice(&self.vals[self.sp - np..self.sp]);
                            self.sp -= np;
                            let r = host.call(self.link[idx], &args[..np], &mut self.mem)?;
                            match (r, ity.n_results) {
                                (Some(v), 1) => self.push(v)?,
                                (None, 0) => {}
                                _ => return Err(Trap::Malformed),
                            }
                            pc = npc;
                        } else {
                            self.frames[self.nframes - 1].pc = npc as u32;
                            self.enter(idx - m.n_imports)?;
                            continue 'frames;
                        }
                    }
                    op::DROP => {
                        self.pop(floor)?;
                        pc = npc;
                    }
                    op::SELECT => {
                        let c = self.pop(floor)?;
                        let b = self.pop(floor)?;
                        let a = self.pop(floor)?;
                        self.push(if c != 0 { a } else { b })?;
                        pc = npc;
                    }
                    op::LOCAL_GET | op::LOCAL_SET | op::LOCAL_TEE => {
                        let (i, _) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                        let slot = locals + i as usize;
                        if slot >= floor {
                            return Err(Trap::Malformed);
                        }
                        match o {
                            op::LOCAL_GET => {
                                let v = self.vals[slot];
                                self.push(v)?;
                            }
                            op::LOCAL_SET => self.vals[slot] = self.pop(floor)?,
                            _ => {
                                let v = self.pop(floor)?;
                                self.vals[slot] = v;
                                self.push(v)?;
                            }
                        }
                        pc = npc;
                    }
                    op::MEMORY_SIZE => {
                        self.push((self.mem.len() / PAGE) as i32)?;
                        pc = npc;
                    }
                    op::I32_CONST => {
                        let (v, _) = leb_i32(code, pc + 1).ok_or(Trap::Malformed)?;
                        self.push(v)?;
                        pc = npc;
                    }
                    _ if is_load(o) || is_store(o) => {
                        let (_, p1) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                        let (offset, _) = leb_u32(code, p1).ok_or(Trap::Malformed)?;
                        let size = access_size(o);
                        if is_load(o) {
                            let base = self.pop(floor)? as u32;
                            let raw = self.mem.load(base, offset, size)?;
                            let v = match o {
                                op::I32_LOAD8_S => raw as u8 as i8 as i32,
                                op::I32_LOAD16_S => raw as u16 as i16 as i32,
                                _ => raw as i32,
                            };
                            self.push(v)?;
                        } else {
                            let val = self.pop(floor)? as u32;
                            let base = self.pop(floor)? as u32;
                            self.mem.store(base, offset, size, val)?;
                        }
                        pc = npc;
                    }
                    op::I32_EQZ => {
                        let a = self.pop(floor)?;
                        self.push((a == 0) as i32)?;
                        pc = npc;
                    }
                    _ if is_numeric(o) => {
                        let b = self.pop(floor)?;
                        let a = self.pop(floor)?;
                        let (ua, ub) = (a as u32, b as u32);
                        let r: i32 = match o {
                            0x46 => (a == b) as i32,
                            0x47 => (a != b) as i32,
                            0x48 => (a < b) as i32,
                            0x49 => (ua < ub) as i32,
                            0x4A => (a > b) as i32,
                            0x4B => (ua > ub) as i32,
                            0x4C => (a <= b) as i32,
                            0x4D => (ua <= ub) as i32,
                            0x4E => (a >= b) as i32,
                            0x4F => (ua >= ub) as i32,
                            0x6A => a.wrapping_add(b),
                            0x6B => a.wrapping_sub(b),
                            0x6C => a.wrapping_mul(b),
                            0x6D => {
                                if b == 0 {
                                    return Err(Trap::DivByZero);
                                }
                                if a == i32::MIN && b == -1 {
                                    return Err(Trap::IntOverflow);
                                }
                                a / b
                            }
                            0x6E => {
                                if b == 0 {
                                    return Err(Trap::DivByZero);
                                }
                                (ua / ub) as i32
                            }
                            0x6F => {
                                if b == 0 {
                                    return Err(Trap::DivByZero);
                                }
                                a.wrapping_rem(b)
                            }
                            0x70 => {
                                if b == 0 {
                                    return Err(Trap::DivByZero);
                                }
                                (ua % ub) as i32
                            }
                            0x71 => a & b,
                            0x72 => a | b,
                            0x73 => a ^ b,
                            0x74 => a.wrapping_shl(ub),
                            0x75 => a.wrapping_shr(ub),
                            _ => ua.wrapping_shr(ub) as i32,
                        };
                        self.push(r)?;
                        pc = npc;
                    }
                    _ => return Err(Trap::Malformed),
                }
            }
        }
    }

    fn push_ctrl(&mut self, is_loop: bool, arity: u8, cont: usize, _floor: usize) -> Result<(), Trap> {
        if self.cp >= CTRL_STACK {
            return Err(Trap::CallDepth);
        }
        self.ctrls[self.cp] = Ctrl { is_loop, arity, height: self.sp as u32, cont: cont as u32 };
        self.cp += 1;
        Ok(())
    }
}

/// Size in bytes of one [`Instance`] (all interpreter stacks are inline, no heap) — for resource accounting.
pub fn size_of_instance() -> usize {
    core::mem::size_of::<Instance<'static, 'static>>()
}
