#!/usr/bin/env python3
"""Per-principal visit counter in the access-controlled KV store (LAW_021).
Anonymous requests (principal 0) get 403; each authenticated principal has a private counter."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
from qswasm import Module

m = Module(memory_pages=1)
m.import_func("kv_get", 4, 1)
m.import_func("kv_put", 4, 1)
m.import_func("resp_status", 1, 0)
m.import_func("resp_content_type", 1, 0)
m.import_func("resp_write", 2, 0)
m.data += [(0, b"a/count"), (16, b'{"error":"forbidden"}'), (40, b'{"count":'), (56, b"}")]
# locals: 0=r 1=cnt 2=dp 3=m
m.func("handle", 0, 1, 4, """
i32.const 0
i32.const 7
i32.const 64
i32.const 8
call $kv_get
local.set 0
local.get 0
i32.const -1
i32.eq
if
  i32.const 403
  call $resp_status
  i32.const 16
  i32.const 21
  call $resp_write
  i32.const 0
  return
end
local.get 0
i32.const -2
i32.ne
if
  i32.const 64
  i32.load8_u
  local.set 1
end
local.get 1
i32.const 1
i32.add
local.set 1
i32.const 64
local.get 1
i32.store8
i32.const 0
i32.const 7
i32.const 64
i32.const 1
call $kv_put
drop
i32.const 200
call $resp_status
i32.const 40
i32.const 9
call $resp_write
local.get 1
local.set 3
i32.const 3010
local.set 2
loop
  local.get 2
  i32.const 1
  i32.sub
  local.set 2
  local.get 2
  local.get 3
  i32.const 10
  i32.rem_u
  i32.const 48
  i32.add
  i32.store8
  local.get 3
  i32.const 10
  i32.div_u
  local.tee 3
  br_if 0
end
local.get 2
i32.const 3010
local.get 2
i32.sub
call $resp_write
i32.const 56
i32.const 1
call $resp_write
i32.const 0
end
""", export="handle")
open(os.path.join(os.path.dirname(__file__), "app.wasm"), "wb").write(m.build())
