//! qedos strict HTTP/1.1 parsing.
//!
//! * `#![no_std]`, no allocation, `#![forbid(unsafe_code)]`.
//! * All results are offsets into the caller's buffer; nothing is copied.
//! * Anything ambiguous is rejected rather than interpreted (request smuggling
//!   defence): bare LF/CR, obs-fold, duplicate Content-Length, CL+TE, TE other
//!   than exactly `chunked`, whitespace before ':', control bytes, absolute-form
//!   targets, CONNECT/TRACE, Upgrade, Expect.
#![no_std]
#![forbid(unsafe_code)]

pub mod chunked;

pub use chunked::{Advance, ChunkDecoder, ChunkError};

/// Maximum size of a request/response head (start line + headers + CRLFCRLF).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Maximum number of header fields in one head.
#[cfg(kani)]
pub const MAX_HEADERS: usize = 2;
#[cfg(not(kani))]
pub const MAX_HEADERS: usize = 64;
/// Maximum request-target length.
pub const MAX_TARGET_BYTES: usize = 2048;

/// A half-open byte range `[start, end)` inside the buffer that was parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    #[inline]
    pub fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.start..self.end]
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Patch,
    Options,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Patch => "PATCH",
            Method::Options => "OPTIONS",
        }
    }
}

/// How the message body is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// No body (requests without CL/TE; HEAD/1xx/204/304 responses).
    None,
    Length(u64),
    Chunked,
    /// Response only: body runs until the peer closes the connection.
    UntilClose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Malformed syntax -> 400.
    Malformed,
    /// Head larger than [`MAX_HEAD_BYTES`] or too many headers -> 431.
    HeadTooLarge,
    /// Target longer than [`MAX_TARGET_BYTES`] -> 414.
    TargetTooLong,
    /// Method syntactically valid but not supported -> 501.
    UnknownMethod,
    /// CONNECT / TRACE -> 405.
    ForbiddenMethod,
    /// Not HTTP/1.1 -> 505.
    UnsupportedVersion,
    /// Upgrade / Expect / unsupported Transfer-Encoding -> 501 (Expect -> 417).
    Unsupported,
    ExpectationFailed,
    /// Conflicting or invalid framing (CL/TE) -> 400.
    BadFraming,
}

impl ParseError {
    pub fn status(self) -> u16 {
        match self {
            ParseError::Malformed | ParseError::BadFraming => 400,
            ParseError::HeadTooLarge => 431,
            ParseError::TargetTooLong => 414,
            ParseError::UnknownMethod | ParseError::Unsupported => 501,
            ParseError::ForbiddenMethod => 405,
            ParseError::UnsupportedVersion => 505,
            ParseError::ExpectationFailed => 417,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Header {
    pub name: Span,
    pub value: Span,
}

/// A fully validated request head.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: Method,
    pub target: Span,
    pub host: Span,
    pub headers: [Header; MAX_HEADERS],
    pub n_headers: usize,
    pub framing: Framing,
    pub keep_alive: bool,
    /// Bytes consumed by the head including the terminating CRLFCRLF.
    pub head_len: usize,
}

impl Request {
    pub fn headers(&self) -> &[Header] {
        &self.headers[..self.n_headers]
    }
}

/// A fully validated response head from a backend.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: [Header; MAX_HEADERS],
    pub n_headers: usize,
    pub framing: Framing,
    /// Backend asked to close (we always send Connection: close anyway).
    pub close: bool,
    pub head_len: usize,
}

impl Response {
    pub fn headers(&self) -> &[Header] {
        &self.headers[..self.n_headers]
    }
}

// ---------------------------------------------------------------------------
// byte classes

#[inline]
pub fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
        | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// Header value bytes: VCHAR, SP, HTAB, obs-text. Never CTLs (incl. CR/LF/NUL).
#[inline]
fn is_value_byte(b: u8) -> bool {
    b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80
}

#[inline]
fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

pub fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if !a[i].eq_ignore_ascii_case(&b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

#[inline]
fn find_byte(s: &[u8], needle: u8) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        if s[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Locate the end of the head: index just past the first CRLFCRLF.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let mut i = 0;
    while i + 3 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

/// Validate line endings of the whole head: every CR is followed by LF and
/// every LF preceded by CR; no other control bytes (HTAB only in values).
fn validate_head_bytes(head: &[u8]) -> Result<(), ParseError> {
    let mut i = 0;
    while i < head.len() {
        let b = head[i];
        match b {
            b'\r' => {
                if i + 1 >= head.len() || head[i + 1] != b'\n' {
                    return Err(ParseError::Malformed);
                }
                i += 2;
                continue;
            }
            b'\n' => return Err(ParseError::Malformed),
            b'\t' => {}
            0x00..=0x1f | 0x7f => return Err(ParseError::Malformed),
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

/// Split `head` (which ends with CRLFCRLF) into lines. Returns start/end of
/// the next line (without CRLF) starting at `pos`, advancing `pos`.
fn next_line(head: &[u8], pos: &mut usize) -> Option<Span> {
    if *pos >= head.len() {
        return None;
    }
    let start = *pos;
    let mut i = start;
    while i + 1 < head.len() {
        if head[i] == b'\r' && head[i + 1] == b'\n' {
            *pos = i + 2;
            return Some(Span { start, end: i });
        }
        i += 1;
    }
    None
}

fn parse_u64_digits(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 19 {
        return None;
    }
    let mut v: u64 = 0;
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
        i += 1;
    }
    Some(v)
}

#[derive(Default)]
struct Framer {
    content_length: Option<u64>,
    chunked: bool,
    seen_te: bool,
    close: bool,
    keep_alive_tok: bool,
}

impl Framer {
    /// Inspect one (name, value) pair. Returns Err for fatal ambiguities.
    fn observe(&mut self, buf: &[u8], name: &[u8], value: Span) -> Result<(), ParseError> {
        if eq_ignore_case(name, b"content-length") {
            if self.content_length.is_some() {
                return Err(ParseError::BadFraming);
            }
            let v = value.slice(buf);
            self.content_length = Some(parse_u64_digits(v).ok_or(ParseError::BadFraming)?);
        } else if eq_ignore_case(name, b"transfer-encoding") {
            if self.seen_te {
                return Err(ParseError::BadFraming);
            }
            self.seen_te = true;
            if !eq_ignore_case(value.slice(buf), b"chunked") {
                // gzip, "chunked, gzip", "identity" ... all refused.
                return Err(ParseError::Unsupported);
            }
            self.chunked = true;
        } else if eq_ignore_case(name, b"connection") {
            // comma-separated tokens (single flat pass without nested loops)
            let v = value.slice(buf);
            let mut tok_start: usize = usize::MAX;
            let mut tok_end: usize = 0;
            let mut i = 0;
            while i <= v.len() {
                let at_delim = i == v.len() || v[i] == b',';
                if !at_delim {
                    if !is_ows(v[i]) {
                        if tok_start == usize::MAX {
                            tok_start = i;
                        }
                        tok_end = i + 1;
                    }
                } else if tok_start != usize::MAX {
                    let tok = &v[tok_start..tok_end];
                    if eq_ignore_case(tok, b"close") {
                        self.close = true;
                    } else if eq_ignore_case(tok, b"keep-alive") {
                        self.keep_alive_tok = true;
                    } else if eq_ignore_case(tok, b"upgrade") {
                        return Err(ParseError::Unsupported);
                    }
                    tok_start = usize::MAX;
                }
                i += 1;
            }
        } else if eq_ignore_case(name, b"upgrade") {
            return Err(ParseError::Unsupported);
        }
        Ok(())
    }

    fn finish(&self) -> Result<Framing, ParseError> {
        match (self.content_length, self.chunked) {
            (Some(_), true) => Err(ParseError::BadFraming),
            (Some(n), false) => Ok(if n == 0 { Framing::None } else { Framing::Length(n) }),
            (None, true) => Ok(Framing::Chunked),
            (None, false) => Ok(Framing::None),
        }
    }
}

/// Parse header lines from `pos` until the blank line.
/// Pushes into `out`, enforcing token names, no obs-fold, no space before ':'.
fn parse_header_block(
    head: &[u8],
    pos: &mut usize,
    out: &mut [Header; MAX_HEADERS],
    framer: &mut Framer,
) -> Result<usize, ParseError> {
    let mut n = 0usize;
    while n <= MAX_HEADERS {
        let line = next_line(head, pos).ok_or(ParseError::Malformed)?;
        if line.is_empty() {
            return Ok(n);
        }
        let l = line.slice(head);
        // obs-fold: line starting with SP/HTAB
        if is_ows(l[0]) {
            return Err(ParseError::Malformed);
        }
        // Single pass over the header line: find ':', validate tchar name,
        // validate value bytes, and compute OWS-trimmed value span.
        let mut colon: usize = usize::MAX;
        let mut v_start: usize = usize::MAX;
        let mut v_end: usize = 0;
        let mut i = 0;
        while i < l.len() {
            let b = l[i];
            if colon == usize::MAX {
                if b == b':' {
                    if i == 0 {
                        return Err(ParseError::Malformed);
                    }
                    colon = i;
                } else if !is_tchar(b) {
                    return Err(ParseError::Malformed); // includes space before ':'
                }
            } else {
                if !is_value_byte(b) {
                    return Err(ParseError::Malformed);
                }
                if !is_ows(b) {
                    if v_start == usize::MAX {
                        v_start = i;
                    }
                    v_end = i + 1;
                }
            }
            i += 1;
        }
        if colon == usize::MAX {
            return Err(ParseError::Malformed);
        }
        if n == MAX_HEADERS {
            return Err(ParseError::HeadTooLarge);
        }
        let name = &l[..colon];
        let value = if v_start == usize::MAX {
            Span { start: line.start + colon + 1, end: line.start + colon + 1 }
        } else {
            Span { start: line.start + v_start, end: line.start + v_end }
        };
        framer.observe(head, name, value)?;
        out[n] = Header { name: Span { start: line.start, end: line.start + colon }, value };
        n += 1;
    }
    Err(ParseError::HeadTooLarge)
}

fn parse_method(m: &[u8]) -> Result<Method, ParseError> {
    match m {
        b"GET" => Ok(Method::Get),
        b"HEAD" => Ok(Method::Head),
        b"POST" => Ok(Method::Post),
        b"PUT" => Ok(Method::Put),
        b"DELETE" => Ok(Method::Delete),
        b"PATCH" => Ok(Method::Patch),
        b"OPTIONS" => Ok(Method::Options),
        b"CONNECT" | b"TRACE" => Err(ParseError::ForbiddenMethod),
        _ => {
            if m.is_empty() {
                return Err(ParseError::Malformed);
            }
            let mut i = 0;
            while i < m.len() {
                if !is_tchar(m[i]) {
                    return Err(ParseError::Malformed);
                }
                i += 1;
            }
            Err(ParseError::UnknownMethod)
        }
    }
}

/// Request-target bytes: origin-form only, printable ASCII, no space, no '#',
/// no backslash. Percent/dot-segment policy is enforced in `pg-policy`.
fn validate_target(t: &[u8]) -> Result<(), ParseError> {
    if t.len() > MAX_TARGET_BYTES {
        return Err(ParseError::TargetTooLong);
    }
    if t.is_empty() || t[0] != b'/' {
        // absolute-form, authority-form, asterisk-form
        return Err(ParseError::Malformed);
    }
    if t.len() >= 2 && t[1] == b'/' {
        // "//host/path" is ambiguous for some backends
        return Err(ParseError::Malformed);
    }
    let mut i = 0;
    while i < t.len() {
        let b = t[i];
        if !(0x21..=0x7e).contains(&b) || b == b'#' || b == b'\\' {
            return Err(ParseError::Malformed);
        }
        i += 1;
    }
    Ok(())
}

fn validate_host(h: &[u8]) -> Result<(), ParseError> {
    if h.is_empty() || h.len() > 255 {
        return Err(ParseError::Malformed);
    }
    let mut i = 0;
    while i < h.len() {
        let b = h[i];
        let ok = b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']' | b'_');
        if !ok {
            return Err(ParseError::Malformed);
        }
        i += 1;
    }
    Ok(())
}

/// Parse a request head from `buf`.
///
/// * `Ok(None)`   — need more bytes.
/// * `Ok(Some())` — complete valid head; `head_len` bytes were consumed.
/// * `Err(e)`     — reject; the caller must send `e.status()` and close.
pub fn parse_request(buf: &[u8]) -> Result<Option<Request>, ParseError> {
    let end = match find_head_end(buf) {
        Some(e) => e,
        None => {
            if buf.len() >= MAX_HEAD_BYTES {
                return Err(ParseError::HeadTooLarge);
            }
            return Ok(None);
        }
    };
    if end > MAX_HEAD_BYTES {
        return Err(ParseError::HeadTooLarge);
    }
    let head = &buf[..end];
    validate_head_bytes(head)?;

    let mut pos = 0usize;
    let line = next_line(head, &mut pos).ok_or(ParseError::Malformed)?;
    let l = line.slice(head);
    // METHOD SP target SP HTTP/1.1  (exactly single spaces)
    let sp1 = find_byte(l, b' ').ok_or(ParseError::Malformed)?;
    let rest = &l[sp1 + 1..];
    let sp2 = find_byte(rest, b' ').ok_or(ParseError::Malformed)?;
    let method = parse_method(&l[..sp1])?;
    let target_bytes = &rest[..sp2];
    let version = &rest[sp2 + 1..];
    validate_target(target_bytes)?;
    if find_byte(version, b' ').is_some() {
        return Err(ParseError::Malformed);
    }
    if version != b"HTTP/1.1" {
        return if version.len() == 8 && version.starts_with(b"HTTP/") {
            Err(ParseError::UnsupportedVersion)
        } else {
            Err(ParseError::Malformed)
        };
    }
    let target = Span {
        start: line.start + sp1 + 1,
        end: line.start + sp1 + 1 + sp2,
    };

    let mut headers = [Header::default(); MAX_HEADERS];
    let mut framer = Framer::default();
    let n = parse_header_block(head, &mut pos, &mut headers, &mut framer)?;
    if pos != head.len() {
        return Err(ParseError::Malformed);
    }

    let mut host: Option<Span> = None;
    let mut hi = 0;
    while hi < n {
        let h = &headers[hi];
        let name = h.name.slice(head);
        if eq_ignore_case(name, b"host") {
            if host.is_some() {
                return Err(ParseError::Malformed);
            }
            validate_host(h.value.slice(head))?;
            host = Some(h.value);
        } else if eq_ignore_case(name, b"expect") {
            return Err(ParseError::ExpectationFailed);
        }
        hi += 1;
    }
    let host = host.ok_or(ParseError::Malformed)?;
    let framing = framer.finish()?;
    // Body on GET/HEAD/DELETE/OPTIONS is legal but rare; allow, framed normally.

    Ok(Some(Request {
        method,
        target,
        host,
        headers,
        n_headers: n,
        framing,
        keep_alive: !framer.close,
        head_len: end,
    }))
}

/// Parse a backend response head. `head_request` suppresses the body.
pub fn parse_response(buf: &[u8], head_request: bool) -> Result<Option<Response>, ParseError> {
    let end = match find_head_end(buf) {
        Some(e) => e,
        None => {
            if buf.len() >= MAX_HEAD_BYTES {
                return Err(ParseError::HeadTooLarge);
            }
            return Ok(None);
        }
    };
    if end > MAX_HEAD_BYTES {
        return Err(ParseError::HeadTooLarge);
    }
    let head = &buf[..end];
    validate_head_bytes(head)?;
    let mut pos = 0usize;
    let line = next_line(head, &mut pos).ok_or(ParseError::Malformed)?;
    let l = line.slice(head);
    // HTTP/1.1 SP 3DIGIT [SP reason]
    if l.len() < 12 || &l[..9] != b"HTTP/1.1 " && &l[..9] != b"HTTP/1.0 " {
        return Err(ParseError::Malformed);
    }
    let code = &l[9..12];
    if !(code[0].is_ascii_digit() && code[1].is_ascii_digit() && code[2].is_ascii_digit()) {
        return Err(ParseError::Malformed);
    }
    if l.len() > 12 && l[12] != b' ' {
        return Err(ParseError::Malformed);
    }
    let status = (code[0] - b'0') as u16 * 100 + (code[1] - b'0') as u16 * 10 + (code[2] - b'0') as u16;
    if !(200..=599).contains(&status) {
        // 1xx interim responses are not supported (we never send Expect).
        return Err(ParseError::Unsupported);
    }
    let mut headers = [Header::default(); MAX_HEADERS];
    let mut framer = Framer::default();
    let n = parse_header_block(head, &mut pos, &mut headers, &mut framer)?;
    let mut framing = framer.finish()?;
    // A Content-Length: 0 response is Framing::None via finish().
    if head_request || status == 204 || status == 304 {
        framing = Framing::None;
    } else if framing == Framing::None && framer.content_length.is_none() {
        framing = Framing::UntilClose;
    }
    Ok(Some(Response {
        status,
        headers,
        n_headers: n,
        framing,
        close: framer.close,
        head_len: end,
    }))
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        414 => "URI Too Long",
        417 => "Expectation Failed",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod proofs;
