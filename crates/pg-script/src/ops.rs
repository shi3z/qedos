//! Opcode table, value types and LEB128 decoders shared by the validator and the interpreter.
//!
//! The accepted instruction set is the WebAssembly 1.0 integer core plus: sign-extension operators,
//! `memory.copy`/`memory.fill` (bulk-memory, active data only), `call_indirect` through one funcref
//! table, mutable/immutable i32/i64 globals and `br_table`. Everything else (f32/f64, SIMD, atomics,
//! reference types, multi-value, passive segments, tail calls, ...) is rejected at load time.

use crate::wasm::LoadError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Ty {
    #[default]
    I32,
    I64,
}

impl Ty {
    pub fn from_byte(b: u8) -> Option<Ty> {
        match b {
            0x7F => Some(Ty::I32),
            0x7E => Some(Ty::I64),
            _ => None,
        }
    }
}

pub mod op {
    pub const UNREACHABLE: u8 = 0x00;
    pub const NOP: u8 = 0x01;
    pub const BLOCK: u8 = 0x02;
    pub const LOOP: u8 = 0x03;
    pub const IF: u8 = 0x04;
    pub const ELSE: u8 = 0x05;
    pub const END: u8 = 0x0B;
    pub const BR: u8 = 0x0C;
    pub const BR_IF: u8 = 0x0D;
    pub const BR_TABLE: u8 = 0x0E;
    pub const RETURN: u8 = 0x0F;
    pub const CALL: u8 = 0x10;
    pub const CALL_INDIRECT: u8 = 0x11;
    pub const DROP: u8 = 0x1A;
    pub const SELECT: u8 = 0x1B;
    pub const LOCAL_GET: u8 = 0x20;
    pub const LOCAL_SET: u8 = 0x21;
    pub const LOCAL_TEE: u8 = 0x22;
    pub const GLOBAL_GET: u8 = 0x23;
    pub const GLOBAL_SET: u8 = 0x24;
    pub const MEMORY_SIZE: u8 = 0x3F;
    pub const MEMORY_GROW: u8 = 0x40;
    pub const I32_CONST: u8 = 0x41;
    pub const I64_CONST: u8 = 0x42;
    pub const PREFIX_FC: u8 = 0xFC;
    pub const FC_MEMORY_COPY: u32 = 0x0A;
    pub const FC_MEMORY_FILL: u32 = 0x0B;
}

/// Memory access descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemOp {
    pub store: bool,
    /// Type of the value moved to/from the operand stack.
    pub ty: Ty,
    /// Bytes touched in memory: 1, 2, 4 or 8.
    pub size: u8,
    /// Sign-extend on load.
    pub signed: bool,
}

pub fn mem_op(o: u8) -> Option<MemOp> {
    use Ty::*;
    let (store, ty, size, signed) = match o {
        0x28 => (false, I32, 4, false),
        0x29 => (false, I64, 8, false),
        0x2C => (false, I32, 1, true),
        0x2D => (false, I32, 1, false),
        0x2E => (false, I32, 2, true),
        0x2F => (false, I32, 2, false),
        0x30 => (false, I64, 1, true),
        0x31 => (false, I64, 1, false),
        0x32 => (false, I64, 2, true),
        0x33 => (false, I64, 2, false),
        0x34 => (false, I64, 4, true),
        0x35 => (false, I64, 4, false),
        0x36 => (true, I32, 4, false),
        0x37 => (true, I64, 8, false),
        0x3A => (true, I32, 1, false),
        0x3B => (true, I32, 2, false),
        0x3C => (true, I64, 1, false),
        0x3D => (true, I64, 2, false),
        0x3E => (true, I64, 4, false),
        _ => return None,
    };
    Some(MemOp { store, ty, size, signed })
}

/// Signature of a plain numeric operator: (operand type, operand count 1|2, result type).
pub fn num_sig(o: u8) -> Option<(Ty, u8, Ty)> {
    use Ty::*;
    Some(match o {
        0x45 => (I32, 1, I32),
        0x46..=0x4F => (I32, 2, I32),
        0x50 => (I64, 1, I32),
        0x51..=0x5A => (I64, 2, I32),
        0x67..=0x69 => (I32, 1, I32),
        0x6A..=0x78 => (I32, 2, I32),
        0x79..=0x7B => (I64, 1, I64),
        0x7C..=0x8A => (I64, 2, I64),
        0xA7 => (I64, 1, I32),       // i32.wrap_i64
        0xAC | 0xAD => (I32, 1, I64), // i64.extend_i32_s/u
        0xC0 | 0xC1 => (I32, 1, I32), // i32.extend8_s/16_s
        0xC2..=0xC4 => (I64, 1, I64), // i64.extend8_s/16_s/32_s
        _ => return None,
    })
}

/// Skip the immediates of `o` (opcode byte already consumed); returns the new pc. `Err` on truncation,
/// non-canonical LEB or an opcode outside the accepted set.
pub fn skip_imm(code: &[u8], pc: usize, o: u8) -> Result<usize, LoadError> {
    use op::*;
    match o {
        UNREACHABLE | NOP | ELSE | END | RETURN | DROP | SELECT => Ok(pc),
        BLOCK | LOOP | IF => match code.get(pc) {
            Some(0x40) | Some(0x7F) | Some(0x7E) => Ok(pc + 1),
            Some(_) => Err(LoadError::UnsupportedType),
            None => Err(LoadError::Truncated),
        },
        BR | BR_IF | CALL | LOCAL_GET | LOCAL_SET | LOCAL_TEE | GLOBAL_GET | GLOBAL_SET => {
            leb_u32(code, pc).map(|(_, p)| p).ok_or(LoadError::BadLeb)
        }
        BR_TABLE => {
            let (n, mut p) = leb_u32(code, pc).ok_or(LoadError::BadLeb)?;
            if n as usize > crate::wasm::MAX_BR_TABLE {
                return Err(LoadError::TooMany);
            }
            let mut i = 0u32;
            while i <= n {
                p = leb_u32(code, p).ok_or(LoadError::BadLeb)?.1;
                i += 1;
            }
            Ok(p)
        }
        CALL_INDIRECT => {
            let (_, p) = leb_u32(code, pc).ok_or(LoadError::BadLeb)?;
            let (t, p) = leb_u32(code, p).ok_or(LoadError::BadLeb)?;
            if t != 0 {
                return Err(LoadError::BadIndex);
            }
            Ok(p)
        }
        I32_CONST => leb_i32(code, pc).map(|(_, p)| p).ok_or(LoadError::BadLeb),
        I64_CONST => leb_i64(code, pc).map(|(_, p)| p).ok_or(LoadError::BadLeb),
        MEMORY_SIZE | MEMORY_GROW => match code.get(pc) {
            Some(0x00) => Ok(pc + 1),
            _ => Err(LoadError::BadMemory),
        },
        PREFIX_FC => {
            let (sub, p) = leb_u32(code, pc).ok_or(LoadError::BadLeb)?;
            match sub {
                FC_MEMORY_COPY => match (code.get(p), code.get(p + 1)) {
                    (Some(0), Some(0)) => Ok(p + 2),
                    _ => Err(LoadError::BadMemory),
                },
                FC_MEMORY_FILL => match code.get(p) {
                    Some(0) => Ok(p + 1),
                    _ => Err(LoadError::BadMemory),
                },
                _ => Err(LoadError::UnsupportedOpcode),
            }
        }
        _ if mem_op(o).is_some() => {
            let (_, p) = leb_u32(code, pc).ok_or(LoadError::BadLeb)?;
            let (_, p) = leb_u32(code, p).ok_or(LoadError::BadLeb)?;
            Ok(p)
        }
        _ if num_sig(o).is_some() => Ok(pc),
        _ => Err(LoadError::UnsupportedOpcode),
    }
}

/// LEB128 u32 (max 5 bytes, unused bits of the last byte must be zero).
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

/// LEB128 s32 (max 5 bytes; high bits of the last byte must be a sign extension).
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

/// LEB128 s64 (max 10 bytes; the 10th byte must be 0x00 or 0x7F).
pub fn leb_i64(b: &[u8], mut p: usize) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(p)?;
        p += 1;
        if shift == 63 {
            if byte != 0x00 && byte != 0x7F {
                return None;
            }
            result |= ((byte & 1) as i64) << 63;
            return Some((result, p));
        }
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                result |= -1i64 << shift;
            }
            return Some((result, p));
        }
    }
}

/// Evaluate a plain numeric operator on already-typed operands. `a` is the first (deeper) operand,
/// `b` the second; unary operators ignore `b`. i32 values are carried zero-extended in a `u64`.
/// Pure and total: every input yields a value or a defined trap (div-by-zero, overflow).
pub fn eval_num(o: u8, a: u64, b: u64) -> Result<u64, crate::wasm::Trap> {
    use crate::wasm::Trap;
    let (a32, b32) = (a as u32, b as u32);
    let (s32a, s32b) = (a32 as i32, b32 as i32);
    let (s64a, s64b) = (a as i64, b as i64);
    let r: u64 = match o {
        // i32 tests / comparisons
        0x45 => (a32 == 0) as u64,
        0x46 => (a32 == b32) as u64,
        0x47 => (a32 != b32) as u64,
        0x48 => (s32a < s32b) as u64,
        0x49 => (a32 < b32) as u64,
        0x4A => (s32a > s32b) as u64,
        0x4B => (a32 > b32) as u64,
        0x4C => (s32a <= s32b) as u64,
        0x4D => (a32 <= b32) as u64,
        0x4E => (s32a >= s32b) as u64,
        0x4F => (a32 >= b32) as u64,
        // i64 tests / comparisons
        0x50 => (a == 0) as u64,
        0x51 => (a == b) as u64,
        0x52 => (a != b) as u64,
        0x53 => (s64a < s64b) as u64,
        0x54 => (a < b) as u64,
        0x55 => (s64a > s64b) as u64,
        0x56 => (a > b) as u64,
        0x57 => (s64a <= s64b) as u64,
        0x58 => (a <= b) as u64,
        0x59 => (s64a >= s64b) as u64,
        0x5A => (a >= b) as u64,
        // i32 arithmetic
        0x67 => a32.leading_zeros() as u64,
        0x68 => a32.trailing_zeros() as u64,
        0x69 => a32.count_ones() as u64,
        0x6A => a32.wrapping_add(b32) as u64,
        0x6B => a32.wrapping_sub(b32) as u64,
        0x6C => a32.wrapping_mul(b32) as u64,
        0x6D => {
            if b32 == 0 {
                return Err(Trap::DivByZero);
            }
            if s32a == i32::MIN && s32b == -1 {
                return Err(Trap::IntOverflow);
            }
            (s32a / s32b) as u32 as u64
        }
        0x6E => {
            if b32 == 0 {
                return Err(Trap::DivByZero);
            }
            (a32 / b32) as u64
        }
        0x6F => {
            if b32 == 0 {
                return Err(Trap::DivByZero);
            }
            s32a.wrapping_rem(s32b) as u32 as u64
        }
        0x70 => {
            if b32 == 0 {
                return Err(Trap::DivByZero);
            }
            (a32 % b32) as u64
        }
        0x71 => (a32 & b32) as u64,
        0x72 => (a32 | b32) as u64,
        0x73 => (a32 ^ b32) as u64,
        0x74 => a32.wrapping_shl(b32) as u64,
        0x75 => s32a.wrapping_shr(b32) as u32 as u64,
        0x76 => a32.wrapping_shr(b32) as u64,
        0x77 => a32.rotate_left(b32 & 31) as u64,
        0x78 => a32.rotate_right(b32 & 31) as u64,
        // i64 arithmetic
        0x79 => a.leading_zeros() as u64,
        0x7A => a.trailing_zeros() as u64,
        0x7B => a.count_ones() as u64,
        0x7C => a.wrapping_add(b),
        0x7D => a.wrapping_sub(b),
        0x7E => a.wrapping_mul(b),
        0x7F => {
            if b == 0 {
                return Err(Trap::DivByZero);
            }
            if s64a == i64::MIN && s64b == -1 {
                return Err(Trap::IntOverflow);
            }
            (s64a / s64b) as u64
        }
        0x80 => {
            if b == 0 {
                return Err(Trap::DivByZero);
            }
            a / b
        }
        0x81 => {
            if b == 0 {
                return Err(Trap::DivByZero);
            }
            s64a.wrapping_rem(s64b) as u64
        }
        0x82 => {
            if b == 0 {
                return Err(Trap::DivByZero);
            }
            a % b
        }
        0x83 => a & b,
        0x84 => a | b,
        0x85 => a ^ b,
        0x86 => a.wrapping_shl(b as u32),
        0x87 => s64a.wrapping_shr(b as u32) as u64,
        0x88 => a.wrapping_shr(b as u32),
        0x89 => a.rotate_left((b & 63) as u32),
        0x8A => a.rotate_right((b & 63) as u32),
        // conversions
        0xA7 => a32 as u64,
        0xAC => s32a as i64 as u64,
        0xAD => a32 as u64,
        0xC0 => (a32 as u8 as i8 as i32) as u32 as u64,
        0xC1 => (a32 as u16 as i16 as i32) as u32 as u64,
        0xC2 => (a as u8 as i8 as i64) as u64,
        0xC3 => (a as u16 as i16 as i64) as u64,
        0xC4 => (a as u32 as i32 as i64) as u64,
        _ => return Err(Trap::Malformed),
    };
    Ok(r)
}
