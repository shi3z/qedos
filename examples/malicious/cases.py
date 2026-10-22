"""Hostile QED Script modules. Every case is *validly signed* with the dev code-signing key unless
`signed=False`; the point is that a signature is not a safety argument — the sandbox must contain them.

expect: ("rejected", "<VerifyError substring>")  -> refused at load, nothing executes
        ("status", N, "<Reason substring>")       -> executed and contained
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
from qswasm import Module

BASE_POLICY = {
    "module": "mal", "version": "1",
    "allow": ["resp_status", "resp_content_type", "resp_write"],
    "max_memory_bytes": "65536", "max_fuel": "100000", "max_stack_depth": "8",
    "max_request_bytes": "4096", "max_response_bytes": "1024", "max_host_calls": "64", "max_exec_us": "50000",
}

def policy_text(**ov):
    p = dict(BASE_POLICY); p.update(ov)
    lines = ["runtime = qs-wasm/1"]
    for k, v in p.items():
        for x in (v if isinstance(v, list) else [v]):
            lines.append(f"{k} = {x}")
    return "\n".join(lines) + "\n"

def mod(asm, imports=(), pages=1, extra=None, nlocals=0):
    m = Module(memory_pages=pages)
    for imp in imports:
        m.import_func(*imp[:3], **({"module": imp[3]} if len(imp) > 3 else {}))
    for e in (extra or []):
        m.func(*e)
    m.func("handle", 0, 1, nlocals, asm, export="handle")
    return m

STD = [("resp_status", 1, 0), ("resp_content_type", 1, 0), ("resp_write", 2, 0)]
OK0 = "\ni32.const 0\nend"

CASES = {}
def case(name, module=None, raw=None, policy=None, expect=None, args=(), signed=True):
    CASES[name] = dict(wasm=raw if raw is not None else module.build(), policy=policy or policy_text(),
                       expect=expect, args=list(args), signed=signed)

case("infinite_loop", mod("loop\nbr 0\nend" + OK0), expect=("status", 503, "OutOfFuel"))
case("oob_load", mod("i32.const -16\ni32.load\ndrop" + OK0), expect=("status", 500, "OutOfBounds"))
case("oob_load_edge", mod("i32.const 65533\ni32.load\ndrop" + OK0), expect=("status", 500, "OutOfBounds"))
case("oob_offset_wrap", mod("i32.const -1\ni32.const 0\ni32.store 4294967295" + OK0), expect=("status", 500, "OutOfBounds"))
case("oob_neg_index", mod("i32.const -1\ni32.load8_u\ndrop" + OK0), expect=("status", 500, "OutOfBounds"))
case("huge_memory_decl", mod("nop" + OK0, pages=17), expect=("rejected", "MemoryTooLarge"))
case("memory_over_policy", mod("nop" + OK0, pages=2), expect=("rejected", "MemoryExceedsPolicy"))
case("call_recursion", mod("call $rec" + OK0, extra=[("rec", 0, 0, 0, "call $rec\nend")]),
     expect=("status", 500, "CallDepth"))
case("value_stack_overflow", mod("i32.const 1\n" * 1100 + OK0), expect=("status", 500, "ValueStackOverflow"))
case("div_overflow", mod("i32.const -2147483648\ni32.const -1\ni32.div_s\ndrop" + OK0), expect=("status", 500, "IntOverflow"))
case("div_zero", mod("i32.const 1\ni32.const 0\ni32.rem_u\ndrop" + OK0), expect=("status", 500, "DivByZero"))
case("wrapping_add_ok", mod("i32.const 2147483647\ni32.const 1\ni32.add\ni32.const -2147483648\ni32.eq\ni32.eqz\nend"),
     expect=("status", 200, "Ok"))
case("unreachable", mod("unreachable" + OK0), expect=("status", 500, "Unreachable"))
case("bad_magic", raw=b"\x00asx\x01\x00\x00\x00", expect=("rejected", "BadMagic"))
case("truncated", raw=b"\x00asm\x01\x00\x00\x00\x01\x05\x01\x60", expect=("rejected", "Module"))
case("garbage", raw=bytes((i * 131 + 7) & 0xFF for i in range(300)), expect=("rejected", "BadMagic"))
case("section_start_fn", raw=b"\x00asm\x01\x00\x00\x00\x08\x01\x00", expect=("rejected", "UnsupportedSection"))
case("float_opcode", mod("f32.const" if False else "byte 0x43\nbyte 0\nbyte 0\nbyte 0\nbyte 0\ndrop" + OK0),
     expect=("rejected", "UnsupportedOpcode"))
case("memory_grow", mod("i32.const 1\nmemory.grow\ndrop" + OK0), expect=("rejected", "UnsupportedOpcode"))
case("import_kv_not_allowed", mod("nop" + OK0, imports=[("kv_get", 4, 1)]), expect=("rejected", "UnsupportedImport"))
case("import_env_system", mod("nop" + OK0, imports=[("system", 1, 1, "env")]), expect=("rejected", "UnsupportedImport"))
case("import_wasi_fd_write", mod("nop" + OK0, imports=[("fd_write", 4, 1, "wasi_snapshot_preview1")]), expect=("rejected", "UnsupportedImport"))
case("import_sel4_cap_copy", mod("nop" + OK0, imports=[("sel4_cap_copy", 2, 1)]), expect=("rejected", "UnsupportedImport"))
case("import_tcp_connect", mod("nop" + OK0, imports=[("tcp_connect", 2, 1)]), expect=("rejected", "UnsupportedImport"))
case("import_tls_key_read", mod("nop" + OK0, imports=[("tls_key_read", 2, 1)]), expect=("rejected", "UnsupportedImport"))
case("import_wrong_arity", mod("nop" + OK0, imports=[("resp_write", 3, 0)]), expect=("rejected", "UnsupportedImport"))
case("host_call_flood", mod("loop\ni32.const 200\ncall $resp_status\nbr 0\nend" + OK0, imports=STD),
     expect=("status", 503, "HostCallLimit"), policy=policy_text(max_fuel="1000000", max_host_calls="100"))
case("output_overflow", mod("i32.const 0\ni32.const 1000\ncall $resp_write\ni32.const 0\ni32.const 1000\ncall $resp_write" + OK0, imports=STD),
     expect=("status", 502, "ResponseTooLarge"))
case("bad_status_code", mod("i32.const 99\ncall $resp_status" + OK0, imports=STD), expect=("status", 500, "HostDenied"))
case("memory_residue_reader", mod("""i32.const 0
i32.const 64
call $resp_write
i32.const 2
i32.const 0
i32.const 64
call $req_field
drop""" + OK0, imports=STD + [("req_field", 3, 1)]),
     policy=policy_text(allow=["resp_status", "resp_content_type", "resp_write", "req_field"]),
     expect=("status", 200, "Ok"), args=["--body", "SECRET-TOKEN-XYZ", "--repeat", "3"])
# Reads a kv key outside its granted prefix / as anonymous and reports denial (-1) via status 200.
for nm, key, principal, expect_status in [
        ("kv_cross_prefix", b"b/secret", "7", 200), ("kv_anonymous", b"a/x", "0", 200)]:
    m = Module(memory_pages=1)
    for imp in STD + [("kv_get", 4, 1)]:
        m.import_func(*imp)
    m.data.append((0, key))
    m.func("handle", 0, 1, 0, f"""i32.const 0
i32.const {len(key)}
i32.const 64
i32.const 32
call $kv_get
i32.const -1
i32.eq
if
  i32.const 200
  call $resp_status
else
  i32.const 500
  call $resp_status
end
i32.const 0
end""", export="handle")
    case(nm, m, policy=policy_text(allow=["resp_status", "resp_content_type", "resp_write", "kv_get"], kv_read="a/"),
         expect=("status", expect_status, "Ok"), args=["--principal", principal])
case("timeout_by_clock", mod("loop\nbr 0\nend" + OK0), expect=("status", 503, "Timeout"),
     policy=policy_text(max_fuel="50000000", max_exec_us="2000"))

# Modules that are also packed into the seL4 test image (tests/test_script_sel4.py): distinct module ids.
case("sel4_spin", mod("loop\nbr 0\nend" + OK0), expect=("status", 503, "Trap("),  # host: Timeout (wall clock); seL4 image: OutOfFuel
     policy=policy_text(module="spin", max_fuel="3000000"))
# Burns the platform-maximum fuel (50M): minutes under QEMU TCG, so the supervisor's wall-clock watchdog must end it.
case("sel4_hang", mod("loop\nbr 0\nend" + OK0), expect=("status", 503, "Trap("),
     policy=policy_text(module="hang", max_fuel="50000000"))
case("sel4_oob", mod("i32.const -16\ni32.load\ndrop" + OK0), expect=("status", 500, "OutOfBounds"),
     policy=policy_text(module="oob"))
case("sel4_leak", mod("""i32.const 0
i32.const 64
call $resp_write
i32.const 2
i32.const 0
i32.const 64
call $req_field
drop""" + OK0, imports=STD + [("req_field", 3, 1)]),
     policy=policy_text(module="leak", allow=["resp_status", "resp_content_type", "resp_write", "req_field"]),
     expect=("status", 200, "Ok"), args=["--body", "SECRET-TOKEN-XYZ", "--repeat", "2"])
