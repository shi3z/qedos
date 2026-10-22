//! Differential-fuzzing support: a typed Wasm program generator (AST -> bytes), byte-level
//! corruptors and an AST shrinker. Host-side tooling only (never part of the TCB).
//!
//! Every generated "valid" program is well-typed by construction and terminates (bounded loops,
//! acyclic calls, indirect calls only from `handle`), so the reference engine (V8) can run it
//! without a fuel limit. Cases are fully determined by `(seed, index)`, which makes any failure
//! reproducible and shrinkable without storing extra state.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum T {
    I32,
    I64,
}
impl T {
    fn byte(self) -> u8 {
        match self {
            T::I32 => 0x7F,
            T::I64 => 0x7E,
        }
    }
}

pub struct Rng(pub u64);
impl Rng {
    pub fn for_case(seed: u64, idx: u64) -> Rng {
        let mut z = seed.wrapping_add(idx.wrapping_mul(0x9E3779B97F4A7C15));
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        Rng(z | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    pub fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

#[derive(Clone, Debug)]
pub enum E {
    Const(T, i64),
    Local(u32),
    Tee(u32, Box<E>),
    Global(u32),
    Un(u8, Box<E>),
    Bin(u8, Box<E>, Box<E>),
    Load(u8, Box<E>, u32),
    Select(Box<E>, Box<E>, Box<E>),
    /// if (cond) (result T) { stmts; e } else { stmts; e }
    If(T, Box<E>, Vec<S>, Box<E>, Vec<S>, Box<E>),
    /// block (result T) { val; cond; br_if 0; drop; fallthrough }
    BrIfVal(T, Box<E>, Box<E>, Box<E>),
    MemSize,
    MemGrow(Box<E>),
    Call(u32, Vec<E>),
    CallIndirect(Vec<T>, Option<T>, Vec<E>, Box<E>),
}

#[derive(Clone, Debug)]
pub enum S {
    Set(u32, E),
    GSet(u32, E),
    Store(u8, E, u32, E),
    Drop(E),
    If(E, Vec<S>, Vec<S>),
    Block(u32, Vec<S>),
    Loop(u32, u8, Vec<S>), // counter local, iterations
    BrIf(u32, E),
    Br(u32),
    BrTable(Vec<u32>, u32, E),
    Return(Option<E>),
    Unreachable,
    Fill(E, E, E),
    Copy(E, E, E),
    CallStmt(u32, Vec<E>),
    Nop,
}

#[derive(Clone, Debug)]
pub struct Func {
    pub params: Vec<T>,
    pub result: Option<T>,
    pub locals: Vec<T>, // declared locals (after params)
    pub body: Vec<S>,
    pub ret: Option<E>,
}

#[derive(Clone, Debug)]
pub struct Prog {
    pub funcs: Vec<Func>, // last one is `handle`
    pub globals: Vec<(T, bool, i64)>,
    pub table: Vec<Option<u32>>, // slot -> helper function index
    pub mem_pages: u32,
    pub mem_max: Option<u32>,
    pub data: Vec<(u32, Vec<u8>)>,
}

// ---------------------------------------------------------------------------------------------
// Generation

const EDGE32: [i64; 12] = [0, 1, -1, 2, 31, 32, 255, 65535, 0x7fff_ffff, -0x8000_0000, 0x1234_5678, 0x8000];
const EDGE64: [i64; 10] = [0, 1, -1, 63, 64, i64::MAX, i64::MIN, 0x1_0000_0000, -0x1_0000_0000, 0xdead_beef_cafe];

struct Gen<'a> {
    r: &'a mut Rng,
    local_tys: Vec<T>,
    n_params: usize,
    ctr_base: u32, // first loop counter local
    globals: Vec<(T, bool, i64)>,
    sigs: Vec<(Vec<T>, Option<T>)>, // helper signatures (callable function indices 0..callable)
    callable: u32,                  // direct calls may target functions < callable
    in_handle: bool,
    table_len: usize,
    mem_bytes: u64,
    labels: Vec<(u32, bool)>, // (id, is_loop)
    next_label: u32,
    loop_depth: u32,
    result: Option<T>,
    /// trap-free mode: keeps programs running to completion so deep code paths are exercised
    safe: bool,
    table: Vec<Option<u32>>,
}

impl<'a> Gen<'a> {
    fn pick_t(&mut self) -> T {
        if self.r.chance(50) {
            T::I32
        } else {
            T::I64
        }
    }
    fn konst(&mut self, t: T) -> i64 {
        match (t, self.r.below(6)) {
            (T::I32, 0..=2) => EDGE32[self.r.below(EDGE32.len() as u64) as usize],
            (T::I32, 3) => self.r.below(300) as i64,
            (T::I32, _) => self.r.next() as i32 as i64,
            (T::I64, 0..=2) => EDGE64[self.r.below(EDGE64.len() as u64) as usize],
            (T::I64, 3) => self.r.below(300) as i64,
            (T::I64, _) => self.r.next() as i64,
        }
    }
    fn locals_of(&self, t: T) -> Vec<u32> {
        (0..self.ctr_base as usize).filter(|i| self.local_tys[*i] == t).map(|i| i as u32).collect()
    }
    fn addr(&mut self, depth: u32) -> E {
        let sz = self.mem_bytes as i64;
        if self.safe {
            let inner = self.expr(T::I32, depth.saturating_sub(1));
            return E::Bin(0x71, Box::new(inner), Box::new(E::Const(T::I32, 0x7fff.min(sz - 64))));
        }
        match self.r.below(20) {
            0..=13 => E::Const(T::I32, self.r.below((sz - 16).max(1) as u64) as i64),
            14 => E::Const(T::I32, sz - 8 + self.r.below(12) as i64),
            15 => E::Const(T::I32, [-1i64, -8, 0x7fff_ffff, 0x8000_0000u32 as i32 as i64][self.r.below(4) as usize]),
            _ => {
                let inner = self.expr(T::I32, depth.saturating_sub(1));
                E::Bin(0x71, Box::new(inner), Box::new(E::Const(T::I32, (sz - 1).min(0xffff))))
            }
        }
    }
    fn offset(&mut self) -> u32 {
        if self.safe {
            return self.r.below(16) as u32;
        }
        match self.r.below(20) {
            0..=13 => 0,
            14..=17 => self.r.below(16) as u32,
            18 => 0xffff_fff0,
            _ => self.r.below(70000) as u32,
        }
    }
    fn expr(&mut self, t: T, depth: u32) -> E {
        if depth == 0 {
            return self.leaf(t);
        }
        let d = depth - 1;
        match self.r.below(24) {
            0 | 1 => self.leaf(t),
            2..=7 => {
                let (lo, n) = if t == T::I32 { (0x6A, 15) } else { (0x7C, 15) };
                let op = lo + self.r.below(n) as u8;
                let lhs = self.expr(t, d);
                let mut rhs = self.expr(t, d);
                let is_divrem = matches!(op, 0x6D..=0x70 | 0x7F..=0x82);
                if is_divrem && (self.safe || self.r.chance(70)) {
                    // positive, non-zero divisor: no DivByZero / IntOverflow in the common case
                    let (and, or) = if t == T::I32 { (0x71, 0x72) } else { (0x83, 0x84) };
                    rhs = E::Bin(or, Box::new(E::Bin(and, Box::new(rhs), Box::new(E::Const(t, 0xffff)))), Box::new(E::Const(t, 1)));
                }
                E::Bin(op, Box::new(lhs), Box::new(rhs))
            }
            8 | 9 => {
                let ops: &[u8] = if t == T::I32 { &[0x67, 0x68, 0x69, 0xC0, 0xC1] } else { &[0x79, 0x7A, 0x7B, 0xC2, 0xC3, 0xC4] };
                let op = ops[self.r.below(ops.len() as u64) as usize];
                E::Un(op, Box::new(self.expr(t, d)))
            }
            10 | 11 => {
                // comparison / eqz of either width (yields i32); widen if an i64 is wanted
                let w = self.pick_t();
                let e = if self.r.chance(15) {
                    E::Un(if w == T::I32 { 0x45 } else { 0x50 }, Box::new(self.expr(w, d)))
                } else {
                    let op = if w == T::I32 { 0x46 + self.r.below(10) as u8 } else { 0x51 + self.r.below(10) as u8 };
                    E::Bin(op, Box::new(self.expr(w, d)), Box::new(self.expr(w, d)))
                };
                if t == T::I64 {
                    E::Un(0xAD, Box::new(e))
                } else {
                    e
                }
            }
            12 | 13 => {
                let (ops, _): (&[u8], ()) = if t == T::I32 {
                    (&[0x28, 0x2C, 0x2D, 0x2E, 0x2F], ())
                } else {
                    (&[0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35], ())
                };
                let op = ops[self.r.below(ops.len() as u64) as usize];
                let a = self.addr(d);
                E::Load(op, Box::new(a), self.offset())
            }
            14 => E::Select(Box::new(self.expr(t, d)), Box::new(self.expr(t, d)), Box::new(self.expr(T::I32, d))),
            15 | 16 => {
                let c = self.expr(T::I32, d);
                let s1 = self.stmts(d, 2);
                let e1 = self.expr(t, d);
                let s2 = self.stmts(d, 2);
                let e2 = self.expr(t, d);
                E::If(t, Box::new(c), s1, Box::new(e1), s2, Box::new(e2))
            }
            17 => E::BrIfVal(t, Box::new(self.expr(t, d)), Box::new(self.expr(T::I32, d)), Box::new(self.expr(t, d))),
            18 => {
                // conversions between widths
                if t == T::I32 {
                    E::Un(0xA7, Box::new(self.expr(T::I64, d)))
                } else {
                    E::Un(0xAC + self.r.below(2) as u8, Box::new(self.expr(T::I32, d)))
                }
            }
            19 => {
                if t == T::I32 {
                    if self.r.chance(50) {
                        E::MemSize
                    } else {
                        let delta = if self.r.chance(70) { E::Const(T::I32, self.r.below(3) as i64) } else { self.expr(T::I32, d) };
                        E::MemGrow(Box::new(delta))
                    }
                } else {
                    self.leaf(t)
                }
            }
            20 | 21 => self.call(t, d).unwrap_or_else(|| self.leaf(t)),
            22 => {
                let l = self.locals_of(t);
                if l.is_empty() {
                    self.leaf(t)
                } else {
                    let i = l[self.r.below(l.len() as u64) as usize];
                    E::Tee(i, Box::new(self.expr(t, d)))
                }
            }
            _ => self.indirect(t, d).unwrap_or_else(|| self.leaf(t)),
        }
    }
    fn leaf(&mut self, t: T) -> E {
        match self.r.below(5) {
            0 | 1 => {
                let l = self.locals_of(t);
                if !l.is_empty() {
                    return E::Local(l[self.r.below(l.len() as u64) as usize]);
                }
                E::Const(t, self.konst(t))
            }
            2 => {
                let g: Vec<u32> = (0..self.globals.len() as u32).filter(|i| self.globals[*i as usize].0 == t).collect();
                if !g.is_empty() {
                    return E::Global(g[self.r.below(g.len() as u64) as usize]);
                }
                E::Const(t, self.konst(t))
            }
            _ => E::Const(t, self.konst(t)),
        }
    }
    fn args(&mut self, params: &[T], d: u32) -> Vec<E> {
        params.iter().map(|p| self.expr(*p, d)).collect()
    }
    fn call(&mut self, t: T, d: u32) -> Option<E> {
        let c: Vec<u32> = (0..self.callable).filter(|i| self.sigs[*i as usize].1 == Some(t)).collect();
        if c.is_empty() {
            return None;
        }
        let f = c[self.r.below(c.len() as u64) as usize];
        let params = self.sigs[f as usize].0.clone();
        Some(E::Call(f, self.args(&params, d)))
    }
    fn indirect(&mut self, t: T, d: u32) -> Option<E> {
        if !self.in_handle || self.table_len == 0 || self.sigs.is_empty() {
            return None;
        }
        if self.safe {
            let live: Vec<usize> = (0..self.table.len())
                .filter(|i| self.table[*i].is_some_and(|f| self.sigs[f as usize].1 == Some(t)))
                .collect();
            if live.is_empty() {
                return None;
            }
            let slot = live[self.r.below(live.len() as u64) as usize];
            let (params, res) = self.sigs[self.table[slot].unwrap() as usize].clone();
            let a = self.args(&params, d);
            return Some(E::CallIndirect(params, res, a, Box::new(E::Const(T::I32, slot as i64))));
        }
        // usually the signature of a real helper that returns `t`; sometimes a mismatching one
        let c: Vec<usize> = (0..self.sigs.len()).filter(|i| self.sigs[*i].1 == Some(t)).collect();
        let (params, res) = if !c.is_empty() && self.r.chance(80) {
            self.sigs[c[self.r.below(c.len() as u64) as usize]].clone()
        } else {
            (vec![self.pick_t()], Some(t))
        };
        let a = self.args(&params, d);
        let slot = if self.r.chance(75) { E::Const(T::I32, self.r.below(self.table_len as u64 + 2) as i64) } else { self.expr(T::I32, d) };
        Some(E::CallIndirect(params, res, a, Box::new(slot)))
    }
    fn stmts(&mut self, depth: u32, max: u64) -> Vec<S> {
        let n = self.r.below(max + 1);
        (0..n).map(|_| self.stmt(depth)).collect()
    }
    fn target_label(&mut self) -> Option<u32> {
        let c: Vec<u32> = self.labels.iter().filter(|l| !l.1).map(|l| l.0).collect();
        if c.is_empty() {
            None
        } else {
            Some(c[self.r.below(c.len() as u64) as usize])
        }
    }
    fn stmt(&mut self, depth: u32) -> S {
        let d = depth.saturating_sub(1);
        match self.r.below(22) {
            0..=3 => {
                let t = self.pick_t();
                let l = self.locals_of(t);
                if l.is_empty() {
                    return S::Nop;
                }
                S::Set(l[self.r.below(l.len() as u64) as usize], self.expr(t, depth))
            }
            4 | 5 => {
                let w: Vec<u32> = (0..self.globals.len() as u32).filter(|i| self.globals[*i as usize].1).collect();
                if w.is_empty() {
                    return S::Nop;
                }
                let g = w[self.r.below(w.len() as u64) as usize];
                S::GSet(g, self.expr(self.globals[g as usize].0, depth))
            }
            6..=8 => {
                let (ops32, ops64): (&[u8], &[u8]) = (&[0x36, 0x3A, 0x3B], &[0x37, 0x3C, 0x3D, 0x3E]);
                let t = self.pick_t();
                let op = if t == T::I32 { ops32[self.r.below(3) as usize] } else { ops64[self.r.below(4) as usize] };
                let a = self.addr(d);
                S::Store(op, a, self.offset(), self.expr(t, d))
            }
            9 => {
                let t = self.pick_t();
                S::Drop(self.expr(t, depth))
            }
            10 | 11 if depth > 0 => S::If(self.expr(T::I32, d), self.stmts(d, 3), self.stmts(d, 3)),
            12 | 13 if depth > 0 => {
                let id = self.next_label;
                self.next_label += 1;
                self.labels.push((id, false));
                let body = self.stmts(d, 4);
                self.labels.pop();
                S::Block(id, body)
            }
            14 | 15 if depth > 0 && self.loop_depth < 3 => {
                let ctr = self.ctr_base + self.loop_depth;
                self.loop_depth += 1;
                let id = self.next_label;
                self.next_label += 1;
                self.labels.push((id, true));
                let body = self.stmts(d, 3);
                self.labels.pop();
                self.loop_depth -= 1;
                S::Loop(ctr, 1 + self.r.below(6) as u8, body)
            }
            16 | 17 => match self.target_label() {
                Some(l) => S::BrIf(l, self.expr(T::I32, d)),
                None => S::Nop,
            },
            18 => {
                let c: Vec<u32> = self.labels.iter().filter(|l| !l.1).map(|l| l.0).collect();
                if c.len() < 1 || self.labels.iter().any(|l| l.1) && false {
                    return S::Nop;
                }
                let n = 1 + self.r.below(4);
                let ts: Vec<u32> = (0..n).map(|_| c[self.r.below(c.len() as u64) as usize]).collect();
                let def = c[self.r.below(c.len() as u64) as usize];
                S::BrTable(ts, def, self.expr(T::I32, d))
            }
            19 => {
                if self.r.chance(60) {
                    S::Fill(self.addr(d), self.expr(T::I32, d), E::Const(T::I32, self.r.below(300) as i64))
                } else {
                    S::Copy(self.addr(d), self.addr(d), E::Const(T::I32, self.r.below(300) as i64))
                }
            }
            20 => {
                let c: Vec<u32> = (0..self.callable).filter(|i| self.sigs[*i as usize].1.is_none()).collect();
                if c.is_empty() {
                    if !self.safe && self.r.chance(3) {
                        return S::Unreachable;
                    }
                    return S::Nop;
                }
                let f = c[self.r.below(c.len() as u64) as usize];
                let params = self.sigs[f as usize].0.clone();
                S::CallStmt(f, self.args(&params, d))
            }
            _ => {
                if !self.safe && self.r.chance(4) {
                    S::Unreachable
                } else if self.r.chance(8) {
                    match self.result {
                        Some(t) => S::Return(Some(self.leaf(t))),
                        None => S::Return(None),
                    }
                } else {
                    S::Nop
                }
            }
        }
    }
}

fn gen_func(r: &mut Rng, sigs: &[(Vec<T>, Option<T>)], idx: usize, globals: &[(T, bool, i64)], in_handle: bool, table: &[Option<u32>], mem_bytes: u64, safe: bool) -> Func {
    let table_len = table.len();
    let (params, result) = sigs[idx].clone();
    let mut locals = vec![T::I32, T::I32, T::I64, T::I64];
    locals.extend([T::I32, T::I32, T::I32]); // loop counters (ctr_base .. ctr_base+3)
    let mut local_tys = params.clone();
    local_tys.extend(locals.iter().copied());
    let ctr_base = (params.len() + 4) as u32;
    let mut g = Gen {
        r,
        local_tys,
        n_params: params.len(),
        ctr_base,
        globals: globals.to_vec(),
        sigs: sigs.to_vec(),
        callable: idx as u32,
        in_handle,
        table_len,
        mem_bytes,
        labels: vec![],
        next_label: 0,
        loop_depth: 0,
        result,
        safe,
        table: table.to_vec(),
    };
    let _ = g.n_params;
    let depth = 3;
    let body = g.stmts(depth, 6);
    let ret = result.map(|t| g.expr(t, depth));
    Func { params, result, locals, body, ret }
}

pub fn gen_prog(r: &mut Rng) -> Prog {
    let n_helpers = r.below(4) as usize;
    let mut sigs: Vec<(Vec<T>, Option<T>)> = (0..n_helpers)
        .map(|_| {
            let np = r.below(4) as usize;
            let ps: Vec<T> = (0..np).map(|_| if r.chance(50) { T::I32 } else { T::I64 }).collect();
            let res = if r.chance(80) { Some(if r.chance(50) { T::I32 } else { T::I64 }) } else { None };
            (ps, res)
        })
        .collect();
    sigs.push((vec![], Some(T::I32))); // handle
    let globals: Vec<(T, bool, i64)> = (0..r.below(4))
        .map(|_| {
            let t = if r.chance(50) { T::I32 } else { T::I64 };
            let v = if t == T::I32 { r.next() as i32 as i64 } else { r.next() as i64 };
            (t, r.chance(70), v)
        })
        .collect();
    let mem_pages = 1 + r.below(2) as u32;
    // always declare a maximum: without one the reference engine may grow past the platform's 16-page hard cap
    let mem_max = Some(mem_pages + r.below(4) as u32);
    let mut table = vec![];
    if n_helpers > 0 && r.chance(70) {
        for _ in 0..(1 + r.below(5)) {
            table.push(if r.chance(80) { Some(r.below(n_helpers as u64) as u32) } else { None });
        }
    }
    let mem_bytes = mem_pages as u64 * 65536;
    let safe = r.chance(40);
    let mut funcs = vec![];
    for i in 0..sigs.len() {
        let last = i == sigs.len() - 1;
        funcs.push(gen_func(r, &sigs, i, &globals, last, &table, mem_bytes, safe));
    }
    let data = (0..r.below(3))
        .map(|_| {
            let len = r.below(40) as usize;
            let off = r.below(mem_bytes - 64) as u32;
            (off, (0..len).map(|_| r.next() as u8).collect())
        })
        .collect();
    Prog { funcs, globals, table, mem_pages, mem_max, data }
}

// ---------------------------------------------------------------------------------------------
// Encoding

fn uleb(mut n: u64, o: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            o.push(b);
            return;
        }
        o.push(b | 0x80);
    }
}
fn sleb(mut v: i64, o: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0) {
            o.push(byte);
            return;
        }
        o.push(byte | 0x80);
    }
}

struct Enc<'a> {
    prog: &'a Prog,
    types: Vec<(Vec<T>, Option<T>)>,
    labels: Vec<(u32, bool)>,
}

impl<'a> Enc<'a> {
    fn type_idx(&mut self, p: &[T], r: Option<T>) -> u32 {
        let k = (p.to_vec(), r);
        if let Some(i) = self.types.iter().position(|t| *t == k) {
            return i as u32;
        }
        self.types.push(k);
        (self.types.len() - 1) as u32
    }
    fn depth_of(&self, id: u32) -> Option<u32> {
        self.labels.iter().rev().position(|l| l.0 == id && !l.1).map(|p| p as u32)
    }
    fn e(&mut self, e: &E, o: &mut Vec<u8>) {
        match e {
            E::Const(t, v) => {
                if *t == T::I32 {
                    o.push(0x41);
                    sleb(*v as i32 as i64, o);
                } else {
                    o.push(0x42);
                    sleb(*v, o);
                }
            }
            E::Local(i) => {
                o.push(0x20);
                uleb(*i as u64, o);
            }
            E::Tee(i, x) => {
                self.e(x, o);
                o.push(0x22);
                uleb(*i as u64, o);
            }
            E::Global(i) => {
                o.push(0x23);
                uleb(*i as u64, o);
            }
            E::Un(op, x) => {
                self.e(x, o);
                o.push(*op);
            }
            E::Bin(op, a, b) => {
                self.e(a, o);
                self.e(b, o);
                o.push(*op);
            }
            E::Load(op, a, off) => {
                self.e(a, o);
                o.push(*op);
                o.push(natural_align(*op));
                uleb(*off as u64, o);
            }
            E::Select(a, b, c) => {
                self.e(a, o);
                self.e(b, o);
                self.e(c, o);
                o.push(0x1B);
            }
            E::If(t, c, s1, e1, s2, e2) => {
                self.e(c, o);
                o.extend_from_slice(&[0x04, t.byte()]);
                self.labels.push((u32::MAX, true)); // anonymous (unbranchable) frame
                for s in s1 {
                    self.s(s, o);
                }
                self.e(e1, o);
                o.push(0x05);
                for s in s2 {
                    self.s(s, o);
                }
                self.e(e2, o);
                self.labels.pop();
                o.push(0x0B);
            }
            E::BrIfVal(t, v, c, f) => {
                o.extend_from_slice(&[0x02, t.byte()]);
                self.labels.push((u32::MAX, true));
                self.e(v, o);
                self.e(c, o);
                o.extend_from_slice(&[0x0D, 0x00, 0x1A]);
                self.e(f, o);
                self.labels.pop();
                o.push(0x0B);
            }
            E::MemSize => o.extend_from_slice(&[0x3F, 0x00]),
            E::MemGrow(d) => {
                self.e(d, o);
                o.extend_from_slice(&[0x40, 0x00]);
            }
            E::Call(f, args) => {
                for a in args {
                    self.e(a, o);
                }
                o.push(0x10);
                uleb(*f as u64, o);
            }
            E::CallIndirect(p, r, args, slot) => {
                for a in args {
                    self.e(a, o);
                }
                self.e(slot, o);
                let ti = self.type_idx(p, *r);
                o.push(0x11);
                uleb(ti as u64, o);
                o.push(0);
            }
        }
    }
    fn block_stmts(&mut self, ss: &[S], o: &mut Vec<u8>) {
        for s in ss {
            self.s(s, o);
        }
    }
    fn s(&mut self, s: &S, o: &mut Vec<u8>) {
        match s {
            S::Set(i, x) => {
                self.e(x, o);
                o.push(0x21);
                uleb(*i as u64, o);
            }
            S::GSet(i, x) => {
                self.e(x, o);
                o.push(0x24);
                uleb(*i as u64, o);
            }
            S::Store(op, a, off, v) => {
                self.e(a, o);
                self.e(v, o);
                o.push(*op);
                o.push(natural_align(*op));
                uleb(*off as u64, o);
            }
            S::Drop(x) => {
                self.e(x, o);
                o.push(0x1A);
            }
            S::If(c, a, b) => {
                self.e(c, o);
                o.extend_from_slice(&[0x04, 0x40]);
                self.labels.push((u32::MAX, true));
                self.block_stmts(a, o);
                o.push(0x05);
                self.block_stmts(b, o);
                self.labels.pop();
                o.push(0x0B);
            }
            S::Block(id, ss) => {
                o.extend_from_slice(&[0x02, 0x40]);
                self.labels.push((*id, false));
                self.block_stmts(ss, o);
                self.labels.pop();
                o.push(0x0B);
            }
            S::Loop(ctr, n, ss) => {
                o.push(0x41);
                sleb(*n as i64, o);
                o.push(0x21);
                uleb(*ctr as u64, o);
                o.extend_from_slice(&[0x03, 0x40]);
                self.labels.push((u32::MAX, true));
                self.block_stmts(ss, o);
                self.labels.pop();
                o.push(0x20);
                uleb(*ctr as u64, o);
                o.extend_from_slice(&[0x41, 1, 0x6B, 0x22]);
                uleb(*ctr as u64, o);
                o.extend_from_slice(&[0x0D, 0x00, 0x0B]);
            }
            S::BrIf(id, c) => {
                if let Some(d) = self.depth_of(*id) {
                    self.e(c, o);
                    o.push(0x0D);
                    uleb(d as u64, o);
                } else {
                    self.e(c, o);
                    o.push(0x1A);
                }
            }
            S::Br(id) => {
                if let Some(d) = self.depth_of(*id) {
                    o.push(0x0C);
                    uleb(d as u64, o);
                }
            }
            S::BrTable(ts, def, sel) => {
                let ds: Vec<Option<u32>> = ts.iter().map(|t| self.depth_of(*t)).collect();
                let dd = self.depth_of(*def);
                if let (true, Some(dd)) = (ds.iter().all(|d| d.is_some()), dd) {
                    self.e(sel, o);
                    o.push(0x0E);
                    uleb(ds.len() as u64, o);
                    for d in ds {
                        uleb(d.unwrap() as u64, o);
                    }
                    uleb(dd as u64, o);
                } else {
                    self.e(sel, o);
                    o.push(0x1A);
                }
            }
            S::Return(x) => {
                if let Some(x) = x {
                    self.e(x, o);
                }
                o.push(0x0F);
            }
            S::Unreachable => o.push(0x00),
            S::Fill(d, v, n) => {
                self.e(d, o);
                self.e(v, o);
                self.e(n, o);
                o.extend_from_slice(&[0xFC, 0x0B, 0x00]);
            }
            S::Copy(d, sr, n) => {
                self.e(d, o);
                self.e(sr, o);
                self.e(n, o);
                o.extend_from_slice(&[0xFC, 0x0A, 0x00, 0x00]);
            }
            S::CallStmt(f, args) => {
                for a in args {
                    self.e(a, o);
                }
                o.push(0x10);
                uleb(*f as u64, o);
            }
            S::Nop => o.push(0x01),
        }
    }
}

fn natural_align(op: u8) -> u8 {
    match op {
        0x29 | 0x37 => 3,
        0x28 | 0x34 | 0x35 | 0x36 | 0x3E => 2,
        0x2E | 0x2F | 0x32 | 0x33 | 0x3B | 0x3D => 1,
        _ => 0,
    }
}

fn section(id: u8, body: &[u8], o: &mut Vec<u8>) {
    o.push(id);
    uleb(body.len() as u64, o);
    o.extend_from_slice(body);
}

impl Prog {
    pub fn encode(&self) -> Vec<u8> {
        let mut enc = Enc { prog: self, types: vec![], labels: vec![] };
        let mut func_ty = vec![];
        for f in &self.funcs {
            func_ty.push(enc.type_idx(&f.params, f.result));
        }
        // bodies first: they may register additional (call_indirect) types
        let mut bodies: Vec<Vec<u8>> = vec![];
        for f in &self.funcs {
            let mut b = vec![];
            // locals: params are implicit; declare in run-length groups
            let mut groups: Vec<(u32, T)> = vec![];
            for t in &f.locals {
                match groups.last_mut() {
                    Some((n, gt)) if gt == t => *n += 1,
                    _ => groups.push((1, *t)),
                }
            }
            uleb(groups.len() as u64, &mut b);
            for (n, t) in groups {
                uleb(n as u64, &mut b);
                b.push(t.byte());
            }
            enc.labels.clear();
            for s in &f.body {
                enc.s(s, &mut b);
            }
            if let Some(r) = &f.ret {
                enc.e(r, &mut b);
            }
            b.push(0x0B);
            let mut w = vec![];
            uleb(b.len() as u64, &mut w);
            w.extend(b);
            bodies.push(w);
        }
        let mut m = b"\0asm\x01\0\0\0".to_vec();
        let mut s = vec![];
        uleb(enc.types.len() as u64, &mut s);
        for (p, r) in &enc.types {
            s.push(0x60);
            uleb(p.len() as u64, &mut s);
            s.extend(p.iter().map(|t| t.byte()));
            uleb(r.is_some() as u64, &mut s);
            if let Some(t) = r {
                s.push(t.byte());
            }
        }
        section(1, &s, &mut m);
        let mut s = vec![];
        uleb(self.funcs.len() as u64, &mut s);
        for t in &func_ty {
            uleb(*t as u64, &mut s);
        }
        section(3, &s, &mut m);
        if !self.table.is_empty() {
            let mut s = vec![1, 0x70, 0];
            uleb(self.table.len() as u64, &mut s);
            section(4, &s, &mut m);
        }
        let mut s = vec![1];
        match self.mem_max {
            None => {
                s.push(0);
                uleb(self.mem_pages as u64, &mut s);
            }
            Some(mx) => {
                s.push(1);
                uleb(self.mem_pages as u64, &mut s);
                uleb(mx as u64, &mut s);
            }
        }
        section(5, &s, &mut m);
        if !self.globals.is_empty() {
            let mut s = vec![];
            uleb(self.globals.len() as u64, &mut s);
            for (t, mu, v) in &self.globals {
                s.push(t.byte());
                s.push(*mu as u8);
                if *t == T::I32 {
                    s.push(0x41);
                    sleb(*v as i32 as i64, &mut s);
                } else {
                    s.push(0x42);
                    sleb(*v, &mut s);
                }
                s.push(0x0B);
            }
            section(6, &s, &mut m);
        }
        let mut s = vec![];
        uleb(2 + self.globals.len() as u64, &mut s);
        for (name, kind, idx) in [("handle", 0u8, (self.funcs.len() - 1) as u64), ("memory", 2, 0)] {
            uleb(name.len() as u64, &mut s);
            s.extend_from_slice(name.as_bytes());
            s.push(kind);
            uleb(idx, &mut s);
        }
        for i in 0..self.globals.len() {
            let name = format!("g{i}");
            uleb(name.len() as u64, &mut s);
            s.extend_from_slice(name.as_bytes());
            s.push(3);
            uleb(i as u64, &mut s);
        }
        section(7, &s, &mut m);
        // element segments: consecutive runs of non-null slots
        let mut runs: Vec<(usize, Vec<u32>)> = vec![];
        for (i, e) in self.table.iter().enumerate() {
            if let Some(f) = e {
                match runs.last_mut() {
                    Some((st, v)) if *st + v.len() == i => v.push(*f),
                    _ => runs.push((i, vec![*f])),
                }
            }
        }
        if !runs.is_empty() {
            let mut s = vec![];
            uleb(runs.len() as u64, &mut s);
            for (st, v) in runs {
                s.push(0);
                s.push(0x41);
                sleb(st as i64, &mut s);
                s.push(0x0B);
                uleb(v.len() as u64, &mut s);
                for f in v {
                    uleb(f as u64, &mut s);
                }
            }
            section(9, &s, &mut m);
        }
        let mut s = vec![];
        uleb(bodies.len() as u64, &mut s);
        for b in bodies {
            s.extend(b);
        }
        section(10, &s, &mut m);
        if !self.data.is_empty() {
            let mut s = vec![];
            uleb(self.data.len() as u64, &mut s);
            for (off, bytes) in &self.data {
                s.push(0);
                s.push(0x41);
                sleb(*off as i64, &mut s);
                s.push(0x0B);
                uleb(bytes.len() as u64, &mut s);
                s.extend_from_slice(bytes);
            }
            section(11, &s, &mut m);
        }
        let _ = enc.prog;
        m
    }
}

// ---------------------------------------------------------------------------------------------
// Corruptors (byte level)

pub fn corrupt(r: &mut Rng, w: &mut Vec<u8>) {
    for _ in 0..(1 + r.below(3)) {
        if w.is_empty() {
            return;
        }
        let i = r.below(w.len() as u64) as usize;
        match r.below(8) {
            0 => w[i] ^= 1 << r.below(8),
            1 => w[i] = r.next() as u8,
            2 => {
                w.remove(i);
            }
            3 => w.insert(i, r.next() as u8),
            4 => w.truncate(i.max(8)),
            5 => {
                // interesting byte values at a random position
                w[i] = [0x00, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x1A, 0x1B, 0x20, 0x40, 0x41, 0x42, 0x7E, 0x7F, 0x80, 0xFC, 0xFF][r.below(19) as usize];
            }
            6 => {
                // duplicate a chunk
                let n = (1 + r.below(8) as usize).min(w.len() - i);
                let chunk: Vec<u8> = w[i..i + n].to_vec();
                for (k, b) in chunk.into_iter().enumerate() {
                    w.insert(i + k, b);
                }
            }
            _ => {
                // swap two bytes
                let j = r.below(w.len() as u64) as usize;
                w.swap(i, j);
            }
        }
    }
}

/// Re-encode every section size as a padded (non-minimal but legal) 5-byte LEB and prepend a custom
/// section: semantically identical, structurally different.
pub fn pad_encoding(r: &mut Rng, w: &[u8]) -> Vec<u8> {
    let mut out = w[..8].to_vec();
    if r.chance(60) {
        let name = b"name";
        out.push(0);
        let body_len = 1 + name.len() + r.below(6) as usize;
        out.push(body_len as u8);
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        out.extend((0..(body_len - 1 - name.len())).map(|_| r.next() as u8));
    }
    let mut p = 8;
    while p < w.len() {
        let id = w[p];
        p += 1;
        let (mut size, mut shift) = (0usize, 0);
        loop {
            let b = w[p];
            p += 1;
            size |= ((b & 0x7f) as usize) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
        }
        out.push(id);
        let s = size as u32;
        out.extend_from_slice(&[(s & 0x7f) as u8 | 0x80, ((s >> 7) & 0x7f) as u8 | 0x80, ((s >> 14) & 0x7f) as u8 | 0x80, ((s >> 21) & 0x7f) as u8 | 0x80, ((s >> 28) & 0x0f) as u8]);
        out.extend_from_slice(&w[p..p + size]);
        p += size;
        if r.chance(15) {
            out.extend_from_slice(&[0, 2, 1, b'x']); // interleaved custom section
        }
    }
    out
}

/// Snippets the loader MUST reject (they are valid WebAssembly that QED Script deliberately excludes).
pub fn forbidden_snippet(r: &mut Rng) -> Vec<u8> {
    let c: &[&[u8]] = &[
        &[0x43, 0, 0, 0, 0, 0x1A],                      // f32.const; drop
        &[0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0x1A],          // f64.const; drop
        &[0x41, 0, 0xB2, 0x1A],                         // f32.convert_i32_s
        &[0x41, 0, 0xBC, 0x1A],                         // i32.reinterpret_f32 (stack-wrong too)
        &[0xD0, 0x70, 0x1A],                            // ref.null func
        &[0xD2, 0x00, 0x1A],                            // ref.func
        &[0x41, 0, 0x25, 0, 0x1A],                      // table.get
        &[0xFC, 0x08, 0x00, 0x00],                      // memory.init
        &[0xFC, 0x09, 0x00],                            // data.drop
        &[0xFC, 0x00, 0x1A],                            // i32.trunc_sat_f32_s
        &[0xFC, 0x0E, 0, 0],                            // table.copy
        &[0xFD, 0x0C],                                  // v128.const prefix
        &[0xFE, 0x03, 0x00],                            // atomic.fence
        &[0x12, 0x00],                                  // return_call
        &[0x13, 0x00, 0x00],                            // return_call_indirect
        &[0x41, 0, 0x1C, 0x01, 0x7F],                   // typed select
        &[0x06, 0x40, 0x0B],                            // try
        &[0x08, 0x00],                                  // throw
        &[0x41, 0, 0x2A, 2, 0, 0x1A],                   // f32.load
        &[0x41, 0, 0x43, 0, 0, 0, 0, 0x38, 2, 0],       // f32.store
        &[0x41, 0, 0x3F, 0x01, 0x1A],                   // memory.size with memory index 1
    ];
    c[r.below(c.len() as u64) as usize].to_vec()
}

pub const CAT_VALID: u8 = 0;
pub const CAT_CORRUPT: u8 = 1;
pub const CAT_PADDED: u8 = 2;
pub const CAT_FORBIDDEN: u8 = 3;

/// Case `(seed, idx)` -> (category, module bytes).
pub fn case(seed: u64, idx: u64) -> (u8, Vec<u8>) {
    let mut r = Rng::for_case(seed, idx);
    let prog = gen_prog(&mut r);
    let mut w = prog.encode();
    match r.below(100) {
        0..=59 => (CAT_VALID, w),
        60..=84 => {
            corrupt(&mut r, &mut w);
            (CAT_CORRUPT, w)
        }
        85..=92 => (CAT_PADDED, pad_encoding(&mut r, &w)),
        _ => {
            // splice a forbidden snippet in front of the first function's final `end`
            let snip = forbidden_snippet(&mut r);
            let mut p2 = prog.clone();
            let h = p2.funcs.len() - 1;
            // easier and robust: encode normally, then locate and patch bytes of the handle body
            let body_end = w.len();
            let _ = (body_end, h);
            // append snippet as an extra *own* function body would shift indices; instead rebuild
            let mut f = p2.funcs[h].clone();
            f.body.insert(0, S::Nop);
            p2.funcs[h] = f;
            let mut bytes = p2.encode();
            // the code section starts with the handle's body last; patch by search for the final `end`
            // of the last function: all bodies end in 0x0B and the data section follows (if any).
            patch_forbidden(&mut bytes, &snip, p2.data.is_empty());
            (CAT_FORBIDDEN, bytes)
        }
    }
}

/// Insert `snip` right before the last function's terminating `end`, fixing the enclosing sizes.
fn patch_forbidden(w: &mut Vec<u8>, snip: &[u8], no_data: bool) {
    // parse sections to find the code section
    let mut p = 8;
    while p < w.len() {
        let id = w[p];
        let sec_start = p;
        p += 1;
        let (mut size, mut shift, mut n) = (0usize, 0, 0);
        loop {
            let b = w[p + n];
            n += 1;
            size |= ((b & 0x7f) as usize) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
        }
        let body_start = p + n;
        if id == 10 {
            // last function body = last (body_len, bytes) of the section: the final byte is `end`
            let end_pos = body_start + size - 1;
            // rebuild: we need to re-encode body_len of the last function and the section size.
            // Locate the last function by scanning forward.
            let mut q = body_start;
            let (cnt, c) = rd_uleb(w, q);
            q += c;
            let mut last_start = q;
            for _ in 0..cnt {
                last_start = q;
                let (fl, c) = rd_uleb(w, q);
                q += c + fl as usize;
            }
            let (fl, c) = rd_uleb(w, last_start);
            let fstart = last_start + c;
            let mut nb = vec![];
            nb.extend_from_slice(&w[fstart..end_pos]);
            nb.extend_from_slice(snip);
            nb.push(0x0B);
            let mut newfunc = vec![];
            uleb(nb.len() as u64, &mut newfunc);
            newfunc.extend(nb);
            let mut sec = w[body_start..last_start].to_vec();
            sec.extend(newfunc);
            let mut hdr = vec![10u8];
            uleb(sec.len() as u64, &mut hdr);
            let mut out = w[..sec_start].to_vec();
            out.extend(hdr);
            out.extend(sec);
            out.extend_from_slice(&w[body_start + size..]);
            let _ = (fl, no_data);
            *w = out;
            return;
        }
        p = body_start + size;
    }
}

fn rd_uleb(w: &[u8], mut p: usize) -> (u64, usize) {
    let (mut v, mut s, mut n) = (0u64, 0, 0);
    loop {
        let b = w[p];
        p += 1;
        n += 1;
        v |= ((b & 0x7f) as u64) << s;
        s += 7;
        if b & 0x80 == 0 {
            return (v, n);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Shrinking

/// Number of shrink "sites" in the program (for the delta-debugging loop).
pub fn shrink_variants(p: &Prog) -> Vec<Prog> {
    let mut out = vec![];
    // drop helper table entries / data / globals are structural; here we shrink bodies only
    for fi in 0..p.funcs.len() {
        // statements: delete one at any nesting level; replace compound statements by their contents
        let mut n = 0;
        count_s(&p.funcs[fi].body, &mut n);
        for k in 0..n {
            let mut q = p.clone();
            let mut c = 0;
            if edit_s(&mut q.funcs[fi].body, k, &mut c, 0) {
                out.push(q);
            }
            let mut q = p.clone();
            let mut c = 0;
            if edit_s(&mut q.funcs[fi].body, k, &mut c, 1) {
                out.push(q);
            }
        }
        // expressions: replace by a constant of the same width / by a child
        let mut n = 0;
        if let Some(r) = &p.funcs[fi].ret {
            count_e(r, &mut n);
        }
        count_s_e(&p.funcs[fi].body, &mut n);
        for k in 0..n {
            for mode in 0..3 {
                let mut q = p.clone();
                let mut c = 0;
                let mut hit = false;
                if let Some(r) = &mut q.funcs[fi].ret {
                    hit |= edit_e(r, k, &mut c, mode);
                }
                if !hit {
                    hit |= edit_s_e(&mut q.funcs[fi].body, k, &mut c, mode);
                }
                if hit {
                    out.push(q);
                }
            }
        }
    }
    out
}

fn count_s(v: &[S], n: &mut usize) {
    for s in v {
        *n += 1;
        match s {
            S::If(_, a, b) => {
                count_s(a, n);
                count_s(b, n);
            }
            S::Block(_, a) | S::Loop(_, _, a) => count_s(a, n),
            _ => {}
        }
    }
}

/// mode 0: delete the k-th statement; mode 1: replace it by its children (if compound) or Nop.
fn edit_s(v: &mut Vec<S>, k: usize, c: &mut usize, mode: u8) -> bool {
    let mut i = 0;
    while i < v.len() {
        if *c == k {
            if mode == 0 {
                v.remove(i);
            } else {
                let inner: Vec<S> = match &v[i] {
                    S::If(_, a, _) => a.clone(),
                    S::Block(_, a) | S::Loop(_, _, a) => a.clone(),
                    _ => return false,
                };
                v.splice(i..=i, inner);
            }
            return true;
        }
        *c += 1;
        let hit = match &mut v[i] {
            S::If(_, a, b) => edit_s(a, k, c, mode) || edit_s(b, k, c, mode),
            S::Block(_, a) | S::Loop(_, _, a) => edit_s(a, k, c, mode),
            _ => false,
        };
        if hit {
            return true;
        }
        i += 1;
    }
    false
}

fn kids_e(e: &E) -> Vec<&E> {
    match e {
        E::Tee(_, x) | E::Un(_, x) | E::MemGrow(x) => vec![x],
        E::Load(_, a, _) => vec![a],
        E::Bin(_, a, b) => vec![a, b],
        E::Select(a, b, c) => vec![a, b, c],
        E::If(_, c, _, e1, _, e2) => vec![c, e1, e2],
        E::BrIfVal(_, a, b, c) => vec![a, b, c],
        E::Call(_, a) => a.iter().collect(),
        E::CallIndirect(_, _, a, s) => a.iter().chain(core::iter::once(&**s)).collect(),
        _ => vec![],
    }
}

fn type_of(e: &E) -> Option<T> {
    Some(match e {
        E::Const(t, _) => *t,
        E::If(t, ..) | E::BrIfVal(t, ..) => *t,
        E::MemSize | E::MemGrow(_) => T::I32,
        E::Un(op, _) => match op {
            0x45 | 0x50 | 0xA7 | 0x67..=0x69 | 0xC0 | 0xC1 => T::I32,
            _ => T::I64,
        },
        E::Bin(op, ..) => {
            if (0x46..=0x4F).contains(op) || (0x51..=0x5A).contains(op) || (0x6A..=0x78).contains(op) {
                T::I32
            } else {
                T::I64
            }
        }
        E::Load(op, ..) => {
            if matches!(op, 0x28 | 0x2C..=0x2F) {
                T::I32
            } else {
                T::I64
            }
        }
        _ => return None, // locals/globals/calls: type depends on context; not replaced by children
    })
}

fn count_e(e: &E, n: &mut usize) {
    *n += 1;
    for k in kids_e(e) {
        count_e(k, n);
    }
    if let E::If(_, _, s1, _, s2, _) = e {
        count_s_e(s1, n);
        count_s_e(s2, n);
    }
}
fn count_s_e(v: &[S], n: &mut usize) {
    for s in v {
        match s {
            S::Set(_, e) | S::GSet(_, e) | S::Drop(e) | S::BrIf(_, e) => count_e(e, n),
            S::Store(_, a, _, b) => {
                count_e(a, n);
                count_e(b, n);
            }
            S::If(c, a, b) => {
                count_e(c, n);
                count_s_e(a, n);
                count_s_e(b, n);
            }
            S::Block(_, a) | S::Loop(_, _, a) => count_s_e(a, n),
            S::BrTable(_, _, e) => count_e(e, n),
            S::Return(Some(e)) => count_e(e, n),
            S::Fill(a, b, c) | S::Copy(a, b, c) => {
                count_e(a, n);
                count_e(b, n);
                count_e(c, n);
            }
            S::CallStmt(_, args) => args.iter().for_each(|a| count_e(a, n)),
            _ => {}
        }
    }
}

/// mode 0: -> Const 0 ; 1: -> Const 1 ; 2: -> first child of the same type
fn edit_e(e: &mut E, k: usize, c: &mut usize, mode: u8) -> bool {
    if *c == k {
        let t = match type_of(e) {
            Some(t) => t,
            None => {
                // locals / globals / calls: only constant replacement keeping the *width* is unknown;
                // skip (the caller will simply try other sites)
                return false;
            }
        };
        match mode {
            0 => *e = E::Const(t, 0),
            1 => *e = E::Const(t, 1),
            _ => {
                let kid = kids_e(e).into_iter().find(|x| type_of(x) == Some(t)).cloned();
                match kid {
                    Some(x) => *e = x,
                    None => return false,
                }
            }
        }
        return true;
    }
    *c += 1;
    match e {
        E::Tee(_, x) | E::Un(_, x) | E::MemGrow(x) | E::Load(_, x, _) => edit_e(x, k, c, mode),
        E::Bin(_, a, b) => edit_e(a, k, c, mode) || edit_e(b, k, c, mode),
        E::Select(a, b, d) | E::BrIfVal(_, a, b, d) => edit_e(a, k, c, mode) || edit_e(b, k, c, mode) || edit_e(d, k, c, mode),
        E::If(_, cnd, s1, e1, s2, e2) => {
            edit_e(cnd, k, c, mode) || edit_e(e1, k, c, mode) || edit_e(e2, k, c, mode) || {
                // statements inside carry expressions too, but their count was added after the kids
                let _ = (s1, s2);
                false
            }
        }
        E::Call(_, a) => a.iter_mut().any(|x| edit_e(x, k, c, mode)),
        E::CallIndirect(_, _, a, s) => a.iter_mut().any(|x| edit_e(x, k, c, mode)) || edit_e(s, k, c, mode),
        _ => false,
    }
}
fn edit_s_e(v: &mut Vec<S>, k: usize, c: &mut usize, mode: u8) -> bool {
    for s in v.iter_mut() {
        let hit = match s {
            S::Set(_, e) | S::GSet(_, e) | S::Drop(e) | S::BrIf(_, e) | S::BrTable(_, _, e) => edit_e(e, k, c, mode),
            S::Return(Some(e)) => edit_e(e, k, c, mode),
            S::Store(_, a, _, b) => edit_e(a, k, c, mode) || edit_e(b, k, c, mode),
            S::If(cnd, a, b) => edit_e(cnd, k, c, mode) || edit_s_e(a, k, c, mode) || edit_s_e(b, k, c, mode),
            S::Block(_, a) | S::Loop(_, _, a) => edit_s_e(a, k, c, mode),
            S::Fill(a, b, d) | S::Copy(a, b, d) => edit_e(a, k, c, mode) || edit_e(b, k, c, mode) || edit_e(d, k, c, mode),
            S::CallStmt(_, args) => args.iter_mut().any(|x| edit_e(x, k, c, mode)),
            _ => false,
        };
        if hit {
            return true;
        }
    }
    false
}

/// Regenerate the AST of a *valid-category* case.
pub fn prog_of_case(seed: u64, idx: u64) -> Prog {
    let mut r = Rng::for_case(seed, idx);
    gen_prog(&mut r)
}
