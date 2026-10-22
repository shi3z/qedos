//! Function-body validation (WebAssembly validation algorithm, heap-free).
//!
//! After a module passes [`validate_body`] the interpreter can rely on: balanced structured control,
//! in-range local/global/function/type/branch indices, correctly typed operands (so no operand stack
//! underflow and no type confusion between i32/i64 slots) and a static upper bound on the operand
//! stack depth of every function. The interpreter still re-checks everything it dereferences
//! (defence in depth), but a validated module never reaches those checks.

use crate::ops::{leb_i32, leb_i64, leb_u32, mem_op, num_sig, op, skip_imm, Ty};
use crate::wasm::{FuncType, LoadError, Module, MAX_NEST, MAX_OPSTACK};

const I32: u8 = 0;
const I64: u8 = 1;
const UNK: u8 = 2; // bottom type: operand popped from unreachable code

fn tcode(t: Ty) -> u8 {
    match t {
        Ty::I32 => I32,
        Ty::I64 => I64,
    }
}

#[derive(Clone, Copy)]
struct CtrlFrame {
    kind: u8, // 0 function, 1 block, 2 loop, 3 if, 4 else
    end: Option<Ty>,
    height: usize,
    unreachable: bool,
}

struct V {
    stack: [u8; MAX_OPSTACK],
    sp: usize,
    max_sp: usize,
    ctrl: [CtrlFrame; MAX_NEST + 1],
    nctrl: usize,
}

impl V {
    fn top(&mut self) -> &mut CtrlFrame {
        &mut self.ctrl[self.nctrl - 1]
    }
    fn push(&mut self, t: u8) -> Result<(), LoadError> {
        if self.sp >= MAX_OPSTACK {
            return Err(LoadError::TooMany);
        }
        self.stack[self.sp] = t;
        self.sp += 1;
        if self.sp > self.max_sp {
            self.max_sp = self.sp;
        }
        Ok(())
    }
    fn pop(&mut self) -> Result<u8, LoadError> {
        let (h, un) = {
            let f = self.top();
            (f.height, f.unreachable)
        };
        if self.sp == h {
            return if un { Ok(UNK) } else { Err(LoadError::TypeMismatch) };
        }
        self.sp -= 1;
        Ok(self.stack[self.sp])
    }
    fn pop_t(&mut self, t: Ty) -> Result<(), LoadError> {
        let got = self.pop()?;
        if got != UNK && got != tcode(t) {
            return Err(LoadError::TypeMismatch);
        }
        Ok(())
    }
    fn pop_opt(&mut self, t: Option<Ty>) -> Result<(), LoadError> {
        match t {
            Some(t) => self.pop_t(t),
            None => Ok(()),
        }
    }
    fn push_opt(&mut self, t: Option<Ty>) -> Result<(), LoadError> {
        match t {
            Some(t) => self.push(tcode(t)),
            None => Ok(()),
        }
    }
    fn set_unreachable(&mut self) {
        let f = self.top();
        f.unreachable = true;
        let h = f.height;
        self.sp = h;
    }
    /// Label type of the frame `l` levels up from the innermost one.
    fn label(&self, l: u32) -> Result<Option<Ty>, LoadError> {
        let l = l as usize;
        if l >= self.nctrl {
            return Err(LoadError::BadIndex);
        }
        let f = &self.ctrl[self.nctrl - 1 - l];
        Ok(if f.kind == 2 { None } else { f.end })
    }
}

fn pop_params(v: &mut V, ty: &FuncType) -> Result<(), LoadError> {
    let mut i = ty.n_params as usize;
    while i > 0 {
        i -= 1;
        v.pop_t(ty.params[i])?;
    }
    Ok(())
}

impl<'a> Module<'a> {
    /// Validate function `fi` (index into the module's own functions). Returns its max operand depth.
    pub(crate) fn validate_body(&self, fi: usize) -> Result<u16, LoadError> {
        let f = &self.funcs[fi];
        let code = f.code;
        let total_funcs = self.n_imports + self.n_funcs;
        let mut v = V {
            stack: [0; MAX_OPSTACK],
            sp: 0,
            max_sp: 0,
            ctrl: [CtrlFrame { kind: 0, end: None, height: 0, unreachable: false }; MAX_NEST + 1],
            nctrl: 1,
        };
        v.ctrl[0] = CtrlFrame { kind: 0, end: f.ty.result(), height: 0, unreachable: false };
        let mut pc = 0usize;
        loop {
            let o = *code.get(pc).ok_or(LoadError::BadControl)?;
            let np = skip_imm(code, pc + 1, o)?;
            let imm = pc + 1;
            match o {
                op::UNREACHABLE => v.set_unreachable(),
                op::NOP => {}
                op::BLOCK | op::LOOP | op::IF => {
                    let bt = match code[imm] {
                        0x40 => None,
                        b => Ty::from_byte(b),
                    };
                    if o == op::IF {
                        v.pop_t(Ty::I32)?;
                    }
                    if v.nctrl > MAX_NEST {
                        return Err(LoadError::TooMany);
                    }
                    let kind = match o {
                        op::BLOCK => 1,
                        op::LOOP => 2,
                        _ => 3,
                    };
                    let h = v.sp;
                    v.ctrl[v.nctrl] = CtrlFrame { kind, end: bt, height: h, unreachable: false };
                    v.nctrl += 1;
                }
                op::ELSE => {
                    let fr = *v.top();
                    if fr.kind != 3 {
                        return Err(LoadError::BadControl);
                    }
                    v.pop_opt(fr.end)?;
                    if v.sp != fr.height {
                        return Err(LoadError::TypeMismatch);
                    }
                    let t = v.top();
                    t.kind = 4;
                    t.unreachable = false;
                }
                op::END => {
                    let fr = *v.top();
                    if fr.kind == 3 && fr.end.is_some() {
                        return Err(LoadError::TypeMismatch); // `if` with a result needs an `else`
                    }
                    v.pop_opt(fr.end)?;
                    if v.sp != fr.height {
                        return Err(LoadError::TypeMismatch);
                    }
                    v.nctrl -= 1;
                    if v.nctrl == 0 {
                        if np != code.len() {
                            return Err(LoadError::BadControl);
                        }
                        return Ok(v.max_sp as u16);
                    }
                    v.push_opt(fr.end)?;
                }
                op::BR => {
                    let (l, _) = leb_u32(code, imm).ok_or(LoadError::BadLeb)?;
                    let lt = v.label(l)?;
                    v.pop_opt(lt)?;
                    v.set_unreachable();
                }
                op::BR_IF => {
                    let (l, _) = leb_u32(code, imm).ok_or(LoadError::BadLeb)?;
                    v.pop_t(Ty::I32)?;
                    let lt = v.label(l)?;
                    v.pop_opt(lt)?;
                    v.push_opt(lt)?;
                }
                op::BR_TABLE => {
                    let (n, mut p) = leb_u32(code, imm).ok_or(LoadError::BadLeb)?;
                    v.pop_t(Ty::I32)?;
                    // default target is the last entry
                    let mut i = 0u32;
                    let mut default_l = 0u32;
                    let mut targets = [0u32; crate::wasm::MAX_BR_TABLE + 1];
                    while i <= n {
                        let (l, q) = leb_u32(code, p).ok_or(LoadError::BadLeb)?;
                        targets[i as usize] = l;
                        default_l = l;
                        p = q;
                        i += 1;
                    }
                    let dt = v.label(default_l)?;
                    let mut j = 0usize;
                    while j <= n as usize {
                        if v.label(targets[j])? != dt {
                            return Err(LoadError::TypeMismatch);
                        }
                        j += 1;
                    }
                    v.pop_opt(dt)?;
                    v.set_unreachable();
                }
                op::RETURN => {
                    v.pop_opt(f.ty.result())?;
                    v.set_unreachable();
                }
                op::CALL => {
                    let (d, _) = leb_u32(code, imm).ok_or(LoadError::BadLeb)?;
                    if d as usize >= total_funcs {
                        return Err(LoadError::BadIndex);
                    }
                    let ty = self.func_type(d as usize);
                    pop_params(&mut v, &ty)?;
                    v.push_opt(ty.result())?;
                }
                op::CALL_INDIRECT => {
                    let (t, _) = leb_u32(code, imm).ok_or(LoadError::BadLeb)?;
                    if self.table_size == 0 {
                        return Err(LoadError::BadIndex);
                    }
                    if t as usize >= self.n_types {
                        return Err(LoadError::BadIndex);
                    }
                    let ty = self.types[t as usize];
                    v.pop_t(Ty::I32)?;
                    pop_params(&mut v, &ty)?;
                    v.push_opt(ty.result())?;
                }
                op::DROP => {
                    v.pop()?;
                }
                op::SELECT => {
                    v.pop_t(Ty::I32)?;
                    let a = v.pop()?;
                    let b = v.pop()?;
                    if a != UNK && b != UNK && a != b {
                        return Err(LoadError::TypeMismatch);
                    }
                    v.push(if a == UNK { b } else { a })?;
                }
                op::LOCAL_GET | op::LOCAL_SET | op::LOCAL_TEE => {
                    let (i, _) = leb_u32(code, imm).ok_or(LoadError::BadLeb)?;
                    if i >= f.n_locals as u32 {
                        return Err(LoadError::BadIndex);
                    }
                    let t = f.local_tys[i as usize];
                    match o {
                        op::LOCAL_GET => v.push(tcode(t))?,
                        op::LOCAL_SET => v.pop_t(t)?,
                        _ => {
                            v.pop_t(t)?;
                            v.push(tcode(t))?;
                        }
                    }
                }
                op::GLOBAL_GET | op::GLOBAL_SET => {
                    let (i, _) = leb_u32(code, imm).ok_or(LoadError::BadLeb)?;
                    if i as usize >= self.n_globals {
                        return Err(LoadError::BadIndex);
                    }
                    let g = self.globals[i as usize];
                    if o == op::GLOBAL_GET {
                        v.push(tcode(g.ty))?;
                    } else {
                        if !g.mutable {
                            return Err(LoadError::TypeMismatch);
                        }
                        v.pop_t(g.ty)?;
                    }
                }
                op::MEMORY_SIZE => {
                    self.need_memory()?;
                    v.push(I32)?;
                }
                op::MEMORY_GROW => {
                    self.need_memory()?;
                    v.pop_t(Ty::I32)?;
                    v.push(I32)?;
                }
                op::I32_CONST => {
                    leb_i32(code, imm).ok_or(LoadError::BadLeb)?;
                    v.push(I32)?;
                }
                op::I64_CONST => {
                    leb_i64(code, imm).ok_or(LoadError::BadLeb)?;
                    v.push(I64)?;
                }
                op::PREFIX_FC => {
                    self.need_memory()?;
                    // copy(dst, src, n) / fill(dst, val, n): three i32 operands, no result
                    v.pop_t(Ty::I32)?;
                    v.pop_t(Ty::I32)?;
                    v.pop_t(Ty::I32)?;
                }
                _ => {
                    if let Some(m) = mem_op(o) {
                        self.need_memory()?;
                        let (align, _) = leb_u32(code, imm).ok_or(LoadError::BadLeb)?;
                        if (1u64 << align.min(63)) > m.size as u64 {
                            return Err(LoadError::BadMemory); // alignment larger than natural
                        }
                        if m.store {
                            v.pop_t(m.ty)?;
                            v.pop_t(Ty::I32)?;
                        } else {
                            v.pop_t(Ty::I32)?;
                            v.push(tcode(m.ty))?;
                        }
                    } else if let Some((ty, n, res)) = num_sig(o) {
                        let mut k = 0;
                        while k < n {
                            v.pop_t(ty)?;
                            k += 1;
                        }
                        v.push(tcode(res))?;
                    } else {
                        return Err(LoadError::UnsupportedOpcode);
                    }
                }
            }
            pc = np;
        }
    }

    fn need_memory(&self) -> Result<(), LoadError> {
        if self.has_memory {
            Ok(())
        } else {
            Err(LoadError::BadMemory)
        }
    }

    pub(crate) fn func_type(&self, idx: usize) -> FuncType {
        if idx < self.n_imports {
            self.imports[idx].ty
        } else {
            self.funcs[idx - self.n_imports].ty
        }
    }
}
