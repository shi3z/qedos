//! Script dispatcher: maps a parsed request target to a script module id.
//!
//! The URL grammar is `/script/<module-id>[/<rest>][?query]`, GET and POST only. Path hygiene is
//! *not* re-implemented: the target is run through the Kani-checked `pg_policy::decide` with a single
//! `Prefix("/script/")` route, so dot-segments, encoded separators, `;`, controls, overlong UTF-8 and
//! the rest of LAW_001's hygiene apply identically to script routes. The module id is then matched
//! against the table of *signed, loaded* modules — client bytes never name code or memory.
use pg_http::Method;
use pg_policy::{decide, split_target, Action, Decision, Pattern, Route};

pub const PREFIX: &[u8] = b"/script/";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptTarget<'a> {
    /// Module identifier (first path segment after the prefix).
    pub module: &'a [u8],
    /// Whole path, e.g. `/script/hello/x`.
    pub path: &'a [u8],
    pub query: &'a [u8],
}

/// `None` => not a script route (caller falls back to the ordinary fixed-route policy / reject).
pub fn script_route(method: Method, target: &[u8]) -> Option<ScriptTarget<'_>> {
    if !matches!(method, Method::Get | Method::Post) {
        return None;
    }
    let routes = [Route { method, pattern: Pattern::Prefix(PREFIX), action: Action::Health }];
    if decide(&routes, method, target) != Decision::Health {
        return None;
    }
    let (path, query) = split_target(target)?;
    let rest = path.get(PREFIX.len()..)?;
    let end = rest.iter().position(|b| *b == b'/').unwrap_or(rest.len());
    let module = &rest[..end];
    if module.is_empty() || module.len() > crate::MAX_MODULE_ID {
        return None;
    }
    Some(ScriptTarget { module, path, query })
}
