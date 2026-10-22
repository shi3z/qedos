//! WebAssembly integer subset: i32/i64 values, one linear memory (growable up to a hard cap), one
//! funcref table, i32/i64 globals, structured control incl. `br_table`/`call_indirect`, sign-extension
//! operators and `memory.copy`/`memory.fill`. No floats, SIMD, threads, WASI, reference types,
//! multi-value, start function or passive segments.
//!
//! Accepted binary sections: type(1), import(2), function(3), table(4), memory(5), global(6),
//! export(7), element(9), datacount(12), code(10), data(11), plus ignored custom(0). Everything
//! else is rejected at load time. Every function body is type-checked by the validator in
//! `validate.rs` before the module can be instantiated.

use crate::ops::{eval_num, mem_op, num_sig, op, skip_imm, Ty};
use pg_script_policy::Limits;

pub use crate::ops::{leb_i32, leb_i64, leb_u32};

pub const PAGE: usize = 65536;
/// Hard cap on linear memory pages (1 MiB) regardless of what the module or policy ask for.
pub const MAX_PAGES: u32 = 16;
pub const MAX_TYPES: usize = 32;
pub const MAX_PARAMS: usize = 8;
pub const MAX_IMPORTS: usize = 16;
pub const MAX_FUNCS: usize = 64;
pub const MAX_DATA: usize = 8;
pub const MAX_LOCALS: usize = 64;
pub const MAX_NEST: usize = 32;
pub const MAX_CALL_DEPTH: usize = 16;
pub const MAX_GLOBALS: usize = 16;
pub const MAX_TABLE: usize = 64;
pub const MAX_ELEM: usize = 8;
pub const MAX_EXPORTS: usize = 32;
pub const MAX_BR_TABLE: usize = 64;
/// Static bound on a function's operand stack depth (enforced by the validator).
pub const MAX_OPSTACK: usize = 256;
pub const VALUE_STACK: usize = 1024;
pub const CTRL_STACK: usize = MAX_NEST * MAX_CALL_DEPTH;
pub const CLOCK_INTERVAL: u32 = 256;
const NULL_ELEM: u8 = 0xFF;

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
    TypeMismatch,
    BadGlobal,
    BadTable,
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
    /// `call_indirect` through a null/out-of-range table slot or with a mismatching signature.
    IndirectCall,
    /// Host function refused the call (policy/ACL denial or bad argument).
    HostDenied,
    Malformed,
}

#[derive(Clone, Copy, Debug)]
pub struct FuncType {
    pub n_params: u8,
    pub n_results: u8,
    pub(crate) params: [Ty; MAX_PARAMS],
    pub(crate) res: Ty,
}

impl Default for FuncType {
    fn default() -> Self {
        FuncType { n_params: 0, n_results: 0, params: [Ty::I32; MAX_PARAMS], res: Ty::I32 }
    }
}

impl PartialEq for FuncType {
    fn eq(&self, o: &Self) -> bool {
        self.n_params == o.n_params
            && self.n_results == o.n_results
            && self.params[..self.n_params as usize] == o.params[..o.n_params as usize]
            && (self.n_results == 0 || self.res == o.res)
    }
}
impl Eq for FuncType {}

impl FuncType {
    /// A signature made only of i32 values (the only kind host functions may have).
    pub fn i32s(n_params: u8, n_results: u8) -> FuncType {
        FuncType { n_params, n_results, params: [Ty::I32; MAX_PARAMS], res: Ty::I32 }
    }
    pub fn all_i32(&self) -> bool {
        self.params[..self.n_params as usize].iter().all(|t| *t == Ty::I32) && (self.n_results == 0 || self.res == Ty::I32)
    }
    pub fn result(&self) -> Option<Ty> {
        if self.n_results == 1 {
            Some(self.res)
        } else {
            None
        }
    }
    pub fn param(&self, i: usize) -> Ty {
        self.params[i]
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Import<'a> {
    pub module: &'a [u8],
    pub name: &'a [u8],
    pub ty: FuncType,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FuncDef<'a> {
    pub ty: FuncType,
    pub n_locals: u8,                   // params + declared locals
    pub local_tys: [Ty; MAX_LOCALS],
    pub code: &'a [u8],                 // instruction bytes, ends with 0x0B
    pub max_stack: u16,                 // validated operand-stack bound
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DataSeg<'a> {
    pub offset: u32,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct GlobalDef {
    pub ty: Ty,
    pub mutable: bool,
    pub init: u64,
}

/// A parsed *and fully validated* module. Fields are private: the only constructor is [`Module::parse`].
#[derive(Clone, Debug)]
pub struct Module<'a> {
    pub(crate) types: [FuncType; MAX_TYPES],
    pub(crate) n_types: usize,
    pub(crate) imports: [Import<'a>; MAX_IMPORTS],
    pub(crate) n_imports: usize,
    pub(crate) funcs: [FuncDef<'a>; MAX_FUNCS],
    pub(crate) n_funcs: usize,
    pub(crate) mem_pages: u32,
    pub(crate) mem_max_pages: u32,
    pub(crate) has_memory: bool,
    pub(crate) data: [DataSeg<'a>; MAX_DATA],
    pub(crate) n_data: usize,
    pub(crate) globals: [GlobalDef; MAX_GLOBALS],
    pub(crate) n_globals: usize,
    pub(crate) table_size: u32,
    pub(crate) table: [u8; MAX_TABLE], // function-space index of each slot, NULL_ELEM when empty
    pub(crate) handle: usize,          // function-index-space index of export "handle"
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
    /// Constant expression: `i32.const x end` or `i64.const x end` (the only forms accepted).
    fn const_expr(&mut self) -> Result<(Ty, u64), LoadError> {
        match self.u8()? {
            op::I32_CONST => {
                let (v, np) = leb_i32(self.b, self.p).ok_or(LoadError::BadLeb)?;
                self.p = np;
                if self.u8()? != op::END {
                    return Err(LoadError::BadData);
                }
                Ok((Ty::I32, v as u32 as u64))
            }
            op::I64_CONST => {
                let (v, np) = leb_i64(self.b, self.p).ok_or(LoadError::BadLeb)?;
                self.p = np;
                if self.u8()? != op::END {
                    return Err(LoadError::BadData);
                }
                Ok((Ty::I64, v as u64))
            }
            _ => Err(LoadError::BadData),
        }
    }
}

fn read_limits(s: &mut Rd<'_>) -> Result<(u32, Option<u32>), LoadError> {
    let flag = s.u8()?;
    let min = s.u32()?;
    match flag {
        0 => Ok((min, None)),
        1 => {
            let max = s.u32()?;
            if max < min {
                return Err(LoadError::BadMemory);
            }
            Ok((min, Some(max)))
        }
        _ => Err(LoadError::BadMemory), // shared memory (threads) rejected
    }
}

impl<'a> Module<'a> {
    pub fn imports(&self) -> &[Import<'a>] {
        &self.imports[..self.n_imports]
    }
    pub fn memory_bytes(&self) -> usize {
        self.mem_pages as usize * PAGE
    }
    /// Largest linear memory (in pages) the module may ever have, before limits are applied.
    pub fn max_memory_pages(&self) -> u32 {
        self.mem_max_pages
    }
    pub fn n_funcs(&self) -> usize {
        self.n_funcs
    }
    /// Static operand-stack bound of own function `i` (validator output).
    pub fn func_max_stack(&self, i: usize) -> u16 {
        self.funcs[i].max_stack
    }
    /// Raw instruction bytes of own function `i` (ends with `end`). Used by the independent
    /// proof checker, which re-derives facts from the same bytes the interpreter runs.
    pub fn func_code(&self, i: usize) -> &'a [u8] {
        self.funcs[i].code
    }
    pub fn n_imports(&self) -> usize {
        self.n_imports
    }
    pub fn handle_index(&self) -> usize {
        self.handle
    }
    pub fn table_len(&self) -> usize {
        self.table_size as usize
    }
    /// Own-function index (not function-space index) stored in table slot `i`, if any.
    pub fn table_entry(&self, i: usize) -> Option<usize> {
        if i >= self.table_size as usize || self.table[i] == NULL_ELEM {
            None
        } else {
            Some(self.table[i] as usize - self.n_imports)
        }
    }

    /// Parse and validate the whole module.
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
        let mut mem_max_pages = 0u32;
        let mut has_memory = false;
        let mut table_size = 0u32;
        let mut has_table = false;
        let mut globals = [GlobalDef { ty: Ty::I32, mutable: false, init: 0 }; MAX_GLOBALS];
        let mut n_globals = 0usize;
        let mut table = [NULL_ELEM; MAX_TABLE];
        let mut handle: Option<u32> = None;
        let empty = FuncDef {
            ty: FuncType::default(),
            n_locals: 0,
            local_tys: [Ty::I32; MAX_LOCALS],
            code: &[],
            max_stack: 0,
        };
        let mut funcs = [empty; MAX_FUNCS];
        let mut n_code = 0usize;
        let mut data = [DataSeg { offset: 0, bytes: &[] }; MAX_DATA];
        let mut n_data = 0usize;
        let mut last_rank = 0u8;
        let mut export_raw: Option<&'a [u8]> = None;
        let mut data_raw: Option<&'a [u8]> = None;
        let mut elem_raw: Option<&'a [u8]> = None;
        let mut datacount: Option<u32> = None;

        while !r.eof() {
            let id = r.u8()?;
            let size = r.u32()? as usize;
            let body = r.bytes(size)?;
            if id == 0 {
                continue;
            }
            let rank = match id {
                1..=7 => id,
                9 => 9,
                12 => 10,
                10 => 11,
                11 => 12,
                _ => return Err(LoadError::UnsupportedSection), // incl. start(8), tag, ...
            };
            if rank <= last_rank {
                return Err(LoadError::SectionOrder);
            }
            last_rank = rank;
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
                        let mut ft = FuncType::default();
                        let mut i = 0;
                        while i < np {
                            ft.params[i] = Ty::from_byte(s.u8()?).ok_or(LoadError::UnsupportedType)?;
                            i += 1;
                        }
                        let nr = s.u32()? as usize;
                        if nr > 1 {
                            return Err(LoadError::UnsupportedType); // multi-value
                        }
                        if nr == 1 {
                            ft.res = Ty::from_byte(s.u8()?).ok_or(LoadError::UnsupportedType)?;
                        }
                        ft.n_params = np as u8;
                        ft.n_results = nr as u8;
                        types[n_types] = ft;
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
                4 => {
                    if s.u32()? != 1 {
                        return Err(LoadError::BadTable);
                    }
                    if s.u8()? != 0x70 {
                        return Err(LoadError::BadTable); // funcref only
                    }
                    let (min, max) = read_limits(&mut s).map_err(|_| LoadError::BadTable)?;
                    if min as usize > MAX_TABLE || max.is_some_and(|m| m as usize > MAX_TABLE) {
                        return Err(LoadError::BadTable);
                    }
                    table_size = min;
                    has_table = true;
                }
                5 => {
                    if s.u32()? != 1 {
                        return Err(LoadError::BadMemory);
                    }
                    let (min, max) = read_limits(&mut s)?;
                    if min > MAX_PAGES {
                        return Err(LoadError::MemoryTooLarge);
                    }
                    mem_pages = min;
                    mem_max_pages = core::cmp::min(max.unwrap_or(MAX_PAGES), MAX_PAGES);
                    has_memory = true;
                }
                6 => {
                    let n = s.u32()? as usize;
                    if n > MAX_GLOBALS {
                        return Err(LoadError::TooMany);
                    }
                    while n_globals < n {
                        let ty = Ty::from_byte(s.u8()?).ok_or(LoadError::BadGlobal)?;
                        let mutable = match s.u8()? {
                            0 => false,
                            1 => true,
                            _ => return Err(LoadError::BadGlobal),
                        };
                        let (ity, init) = s.const_expr().map_err(|_| LoadError::BadGlobal)?;
                        if ity != ty {
                            return Err(LoadError::BadGlobal);
                        }
                        globals[n_globals] = GlobalDef { ty, mutable, init };
                        n_globals += 1;
                    }
                }
                7 => export_raw = Some(body),
                9 => elem_raw = Some(body),
                12 => datacount = Some(s.u32()?),
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
                        let mut local_tys = [Ty::I32; MAX_LOCALS];
                        let mut total = ty.n_params as usize;
                        local_tys[..total].copy_from_slice(&ty.params[..total]);
                        let mut g = 0;
                        while g < ngroups {
                            let cnt = f.u32()? as usize;
                            let lt = Ty::from_byte(f.u8()?).ok_or(LoadError::UnsupportedType)?;
                            let new_total = total.checked_add(cnt).ok_or(LoadError::TooMany)?;
                            if new_total > MAX_LOCALS {
                                return Err(LoadError::TooMany);
                            }
                            let mut k = total;
                            while k < new_total {
                                local_tys[k] = lt;
                                k += 1;
                            }
                            total = new_total;
                            g += 1;
                        }
                        funcs[n_code] = FuncDef {
                            ty,
                            n_locals: total as u8,
                            local_tys,
                            code: &fb[f.p..],
                            max_stack: 0,
                        };
                        n_code += 1;
                    }
                }
                11 => data_raw = Some(body),
                _ => return Err(LoadError::UnsupportedSection),
            }
            if !s.eof() && id != 7 && id != 11 && id != 9 {
                return Err(LoadError::BadFunction);
            }
        }
        if n_code != n_funcs {
            return Err(LoadError::BadFunction);
        }
        let total_funcs = n_imports + n_funcs;
        // exports
        let mut n_exports = 0usize;
        if let Some(raw) = export_raw {
            let mut s = Rd { b: raw, p: 0 };
            let n = s.u32()?;
            let mut i = 0;
            while i < n {
                let nl = s.u32()? as usize;
                let name = s.bytes(nl)?;
                let kind = s.u8()?;
                let idx = s.u32()? as usize;
                n_exports += 1;
                if n_exports > MAX_EXPORTS {
                    return Err(LoadError::TooMany);
                }
                match kind {
                    0x00 => {
                        if idx >= total_funcs {
                            return Err(LoadError::BadIndex);
                        }
                        if name == b"handle" {
                            if handle.is_some() {
                                return Err(LoadError::BadFunction);
                            }
                            handle = Some(idx as u32);
                        }
                    }
                    0x01 if idx != 0 || !has_table => return Err(LoadError::BadIndex),
                    0x02 if idx != 0 || !has_memory => return Err(LoadError::BadIndex),
                    0x03 if idx >= n_globals => return Err(LoadError::BadIndex),
                    0x01..=0x03 => {}
                    _ => return Err(LoadError::BadFunction),
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
        if hty.n_params != 0 || hty.result() != Some(Ty::I32) {
            return Err(LoadError::NoHandle);
        }
        // element segments: active, table 0, `i32.const off`, vector of own-function indices
        if let Some(raw) = elem_raw {
            let mut s = Rd { b: raw, p: 0 };
            let n = s.u32()? as usize;
            if n > MAX_ELEM {
                return Err(LoadError::TooMany);
            }
            let mut k = 0;
            while k < n {
                if !has_table || s.u32()? != 0 {
                    return Err(LoadError::BadTable);
                }
                let (oty, off) = s.const_expr().map_err(|_| LoadError::BadTable)?;
                if oty != Ty::I32 {
                    return Err(LoadError::BadTable);
                }
                let off = off as u32 as i32;
                let cnt = s.u32()? as usize;
                if off < 0 || off as u64 + cnt as u64 > table_size as u64 {
                    return Err(LoadError::BadTable);
                }
                let mut j = 0;
                while j < cnt {
                    let fi = s.u32()? as usize;
                    // imports cannot be reached indirectly: only module-defined functions
                    if fi < n_imports || fi >= total_funcs {
                        return Err(LoadError::BadTable);
                    }
                    table[off as usize + j] = fi as u8;
                    j += 1;
                }
                k += 1;
            }
            if !s.eof() {
                return Err(LoadError::BadTable);
            }
        }
        // data segments: active, memory 0, `i32.const off`
        let mut n_data_decl = 0u32;
        if let Some(raw) = data_raw {
            let mut s = Rd { b: raw, p: 0 };
            let n = s.u32()? as usize;
            if n > MAX_DATA {
                return Err(LoadError::TooMany);
            }
            n_data_decl = n as u32;
            while n_data < n {
                if s.u32()? != 0 || !has_memory {
                    return Err(LoadError::BadData);
                }
                let (oty, off) = s.const_expr()?;
                let off = off as u32 as i32;
                if oty != Ty::I32 || off < 0 {
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
        if let Some(c) = datacount {
            if c != n_data_decl {
                return Err(LoadError::BadData);
            }
        }
        let mut m = Module {
            types,
            n_types,
            imports,
            n_imports,
            funcs,
            n_funcs,
            mem_pages,
            mem_max_pages,
            has_memory,
            data,
            n_data,
            globals,
            n_globals,
            table_size,
            table,
            handle,
        };
        let mut i = 0;
        while i < n_funcs {
            m.funcs[i].max_stack = m.validate_body(i)?;
            i += 1;
        }
        Ok(m)
    }
}

// ---------------------------------------------------------------------------
// Memory

/// Bounds-checked linear memory view. All guest and host accesses go through [`checked_range`].
/// `buf` is the whole scratch region; only `[0, len)` is addressable by the guest, `len` can grow
/// (never shrink) up to `cap`.
pub struct Memory<'m> {
    pub(crate) buf: &'m mut [u8],
    pub(crate) len: usize,
    pub(crate) cap: usize,
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
    /// `len` bytes are currently addressable, growth is allowed up to `cap` bytes (`cap <= buf.len()`).
    pub fn new(buf: &'m mut [u8], len: usize, cap: usize) -> Memory<'m> {
        let cap = core::cmp::min(cap, buf.len());
        let len = core::cmp::min(len, cap);
        Memory { buf, len, cap }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    /// Range `[ptr, ptr+len)` for host functions; `ptr`/`len` are guest i32s interpreted as u32.
    pub fn range(&self, ptr: i32, len: i32) -> Result<core::ops::Range<usize>, Trap> {
        let s = checked_range(self.len, ptr as u32, 0, len as u32).ok_or(Trap::OutOfBounds)?;
        Ok(s..s + len as u32 as usize)
    }
    pub fn slice(&self, ptr: i32, len: i32) -> Result<&[u8], Trap> {
        let r = self.range(ptr, len)?;
        Ok(&self.buf[r])
    }
    pub fn slice_mut(&mut self, ptr: i32, len: i32) -> Result<&mut [u8], Trap> {
        let r = self.range(ptr, len)?;
        Ok(&mut self.buf[r])
    }
    pub(crate) fn load(&self, base: u32, offset: u32, size: u32) -> Result<u64, Trap> {
        let s = checked_range(self.len, base, offset, size).ok_or(Trap::OutOfBounds)?;
        let mut v = 0u64;
        let mut i = 0usize;
        while i < size as usize {
            v |= (self.buf[s + i] as u64) << (8 * i);
            i += 1;
        }
        Ok(v)
    }
    pub(crate) fn store(&mut self, base: u32, offset: u32, size: u32, val: u64) -> Result<(), Trap> {
        let s = checked_range(self.len, base, offset, size).ok_or(Trap::OutOfBounds)?;
        let mut i = 0usize;
        while i < size as usize {
            self.buf[s + i] = (val >> (8 * i)) as u8;
            i += 1;
        }
        Ok(())
    }
    /// `memory.grow`: returns the previous size in pages, or `None` if it would exceed `cap`.
    /// New pages are explicitly zeroed (the scratch region may hold a previous tenant's bytes).
    pub(crate) fn grow(&mut self, delta_pages: u32) -> Option<u32> {
        let old = self.len / PAGE;
        let new_pages = (old as u64).checked_add(delta_pages as u64)?;
        let new_len = new_pages.checked_mul(PAGE as u64)?;
        if new_len > self.cap as u64 {
            return None;
        }
        let new_len = new_len as usize;
        let mut i = self.len;
        while i < new_len {
            self.buf[i] = 0;
            i += 1;
        }
        self.len = new_len;
        Some(old as u32)
    }
    /// Zero every byte the guest could have written (called when the instance is dropped).
    fn scrub(&mut self) {
        let mut i = 0;
        while i < self.len {
            self.buf[i] = 0;
            i += 1;
        }
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
    globals: [u64; MAX_GLOBALS],
    vals: [u64; VALUE_STACK],
    sp: usize,
    ctrls: [Ctrl; CTRL_STACK],
    cp: usize,
    frames: [Frame; MAX_CALL_DEPTH],
    nframes: usize,
}

impl<'a, 'm> Drop for Instance<'a, 'm> {
    fn drop(&mut self) {
        self.mem.scrub();
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
        // growth ceiling: module max, hard cap, policy limit and the scratch buffer, whichever is smallest
        let cap = core::cmp::min(
            module.mem_max_pages as usize * PAGE,
            core::cmp::min(limits.max_memory_bytes as usize, mem.len()),
        );
        let cap = cap - cap % PAGE;
        let mem = Memory::new(mem, size, core::cmp::max(cap, size));
        let mut k = 0;
        while k < size {
            mem.buf[k] = 0;
            k += 1;
        }
        let mut d = 0;
        while d < module.n_data {
            let seg = &module.data[d];
            let o = seg.offset as usize;
            mem.buf[o..o + seg.bytes.len()].copy_from_slice(seg.bytes);
            d += 1;
        }
        let mut globals = [0u64; MAX_GLOBALS];
        let mut g = 0;
        while g < module.n_globals {
            globals[g] = module.globals[g].init;
            g += 1;
        }
        Ok(Instance {
            module,
            mem,
            link,
            limits,
            fuel: limits.max_fuel as u64,
            host_calls: 0,
            globals,
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
    /// Current linear memory contents.
    pub fn memory(&self) -> &[u8] {
        self.mem.bytes()
    }
    pub fn global(&self, i: usize) -> Option<u64> {
        if i < self.module.n_globals {
            Some(self.globals[i])
        } else {
            None
        }
    }

    #[inline]
    fn push(&mut self, v: u64) -> Result<(), Trap> {
        if self.sp >= VALUE_STACK {
            return Err(Trap::ValueStackOverflow);
        }
        self.vals[self.sp] = v;
        self.sp += 1;
        Ok(())
    }
    #[inline]
    fn pop(&mut self, floor: usize) -> Result<u64, Trap> {
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
        // static operand bound from the validator: after this check no push in this frame can overflow
        if self.sp + extra + def.max_stack as usize > VALUE_STACK {
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
        Ok(self.vals[0] as u32 as i32)
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
            macro_rules! branch {
                ($d:expr) => {{
                    let d = $d as usize;
                    let open = self.cp - ctrl_base;
                    if d == open {
                        do_return!();
                    }
                    if d > open {
                        return Err(Trap::Malformed);
                    }
                    let ti = self.cp - 1 - d;
                    let c = self.ctrls[ti];
                    let keep = if c.arity == 1 { Some(self.pop(floor)?) } else { None };
                    if (c.height as usize) > self.sp {
                        return Err(Trap::Malformed);
                    }
                    self.sp = c.height as usize;
                    if let Some(v) = keep {
                        self.push(v)?;
                    }
                    self.cp = if c.is_loop { ti + 1 } else { ti };
                    pc = c.cont as usize;
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
                        let arity = if code[pc + 1] == 0x40 { 0 } else { 1 };
                        let (els, end, steps) = Self::scan(code, npc)?;
                        self.burn(steps)?;
                        let mut cond = true;
                        if o == op::IF {
                            cond = self.pop(floor)? as u32 != 0;
                        }
                        if o == op::IF && !cond {
                            match els {
                                Some(e) => {
                                    self.push_ctrl(false, arity, end)?;
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
                    op::BR => {
                        let (d, _) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                        branch!(d);
                    }
                    op::BR_IF => {
                        let (d, _) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                        if self.pop(floor)? as u32 != 0 {
                            branch!(d);
                        } else {
                            pc = npc;
                        }
                    }
                    op::BR_TABLE => {
                        let sel = self.pop(floor)? as u32;
                        let (n, mut p) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                        let want = core::cmp::min(sel, n);
                        let mut k = 0u32;
                        let target = loop {
                            let (l, q) = leb_u32(code, p).ok_or(Trap::Malformed)?;
                            if k == want {
                                break l;
                            }
                            p = q;
                            k += 1;
                        };
                        branch!(target);
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
                            let mut a = 0;
                            while a < np {
                                args[a] = self.vals[self.sp - np + a] as u32 as i32;
                                a += 1;
                            }
                            self.sp -= np;
                            let r = host.call(self.link[idx], &args[..np], &mut self.mem)?;
                            match (r, ity.n_results) {
                                (Some(v), 1) => self.push(v as u32 as u64)?,
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
                    op::CALL_INDIRECT => {
                        let (tidx, _) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                        let slot = self.pop(floor)? as u32;
                        if slot >= m.table_size {
                            return Err(Trap::IndirectCall);
                        }
                        let target = m.table[slot as usize];
                        if target == NULL_ELEM {
                            return Err(Trap::IndirectCall);
                        }
                        let target = target as usize;
                        let want = m.types.get(tidx as usize).ok_or(Trap::Malformed)?;
                        if target < m.n_imports || m.func_type(target) != *want {
                            return Err(Trap::IndirectCall);
                        }
                        self.frames[self.nframes - 1].pc = npc as u32;
                        self.enter(target - m.n_imports)?;
                        continue 'frames;
                    }
                    op::DROP => {
                        self.pop(floor)?;
                        pc = npc;
                    }
                    op::SELECT => {
                        let c = self.pop(floor)? as u32;
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
                    op::GLOBAL_GET | op::GLOBAL_SET => {
                        let (i, _) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                        let i = i as usize;
                        if i >= m.n_globals {
                            return Err(Trap::Malformed);
                        }
                        if o == op::GLOBAL_GET {
                            let v = self.globals[i];
                            self.push(v)?;
                        } else {
                            if !m.globals[i].mutable {
                                return Err(Trap::Malformed);
                            }
                            self.globals[i] = self.pop(floor)?;
                        }
                        pc = npc;
                    }
                    op::MEMORY_SIZE => {
                        self.push((self.mem.len() / PAGE) as u64)?;
                        pc = npc;
                    }
                    op::MEMORY_GROW => {
                        let delta = self.pop(floor)? as u32;
                        self.burn(delta.min(MAX_PAGES) as u64 * 256)?; // zeroing cost
                        let r = match self.mem.grow(delta) {
                            Some(old) => old,
                            None => u32::MAX, // -1
                        };
                        self.push(r as u64)?;
                        pc = npc;
                    }
                    op::I32_CONST => {
                        let (v, _) = leb_i32(code, pc + 1).ok_or(Trap::Malformed)?;
                        self.push(v as u32 as u64)?;
                        pc = npc;
                    }
                    op::I64_CONST => {
                        let (v, _) = leb_i64(code, pc + 1).ok_or(Trap::Malformed)?;
                        self.push(v as u64)?;
                        pc = npc;
                    }
                    op::PREFIX_FC => {
                        let (sub, _) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                        let n = self.pop(floor)? as u32;
                        let b = self.pop(floor)? as u32; // src (copy) or fill byte (fill)
                        let dst = self.pop(floor)? as u32;
                        self.burn(n as u64 / 64)?;
                        let len = self.mem.len;
                        let d = checked_range(len, dst, 0, n).ok_or(Trap::OutOfBounds)?;
                        match sub {
                            op::FC_MEMORY_COPY => {
                                let s = checked_range(len, b, 0, n).ok_or(Trap::OutOfBounds)?;
                                self.mem.buf.copy_within(s..s + n as usize, d);
                            }
                            op::FC_MEMORY_FILL => {
                                let byte = b as u8;
                                let mut i = 0usize;
                                while i < n as usize {
                                    self.mem.buf[d + i] = byte;
                                    i += 1;
                                }
                            }
                            _ => return Err(Trap::Malformed),
                        }
                        pc = npc;
                    }
                    _ => {
                        if let Some(mo) = mem_op(o) {
                            let (_, p1) = leb_u32(code, pc + 1).ok_or(Trap::Malformed)?;
                            let (offset, _) = leb_u32(code, p1).ok_or(Trap::Malformed)?;
                            let size = mo.size as u32;
                            if mo.store {
                                let val = self.pop(floor)?;
                                let base = self.pop(floor)? as u32;
                                self.mem.store(base, offset, size, val)?;
                            } else {
                                let base = self.pop(floor)? as u32;
                                let raw = self.mem.load(base, offset, size)?;
                                let v = if mo.signed {
                                    let sh = 64 - 8 * size;
                                    let sx = (((raw << sh) as i64) >> sh) as u64;
                                    if mo.ty == Ty::I32 {
                                        sx as u32 as u64
                                    } else {
                                        sx
                                    }
                                } else {
                                    raw
                                };
                                self.push(v)?;
                            }
                            pc = npc;
                        } else if let Some((_, n, _)) = num_sig(o) {
                            let b = if n == 2 { self.pop(floor)? } else { 0 };
                            let a = self.pop(floor)?;
                            let r = eval_num(o, a, b)?;
                            self.push(r)?;
                            pc = npc;
                        } else {
                            return Err(Trap::Malformed);
                        }
                    }
                }
            }
        }
    }

    fn push_ctrl(&mut self, is_loop: bool, arity: u8, cont: usize) -> Result<(), Trap> {
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
