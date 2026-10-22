#!/usr/bin/env python3
"""Echo-style handler: copies a request field (default: POST body), uppercases it into a JSON string
and reports its length.  `make(field=1)` builds the URL-parameter variant used by examples/params."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
from qswasm import Module

# locals: 0=n 1=i 2=c 3=dp 4=addr 5=m
ASM = """
  i32.const {FIELD}
  i32.const 1024
  i32.const 2048
  call $req_field
  local.set 0
  local.get 0
  i32.const 0
  i32.lt_s
  if
    i32.const 0
    local.set 0
  end
  local.get 0
  i32.const 2048
  i32.gt_s
  if
    i32.const 2048
    local.set 0
  end
  block
    loop
      local.get 1
      local.get 0
      i32.ge_u
      br_if 1
      local.get 1
      i32.const 1024
      i32.add
      local.tee 4
      i32.load8_u
      local.set 2
      local.get 2
      i32.const 34
      i32.eq
      local.get 2
      i32.const 92
      i32.eq
      i32.or
      local.get 2
      i32.const 32
      i32.lt_u
      i32.or
      if
        i32.const 95
        local.set 2
      else
        local.get 2
        i32.const 97
        i32.sub
        i32.const 26
        i32.lt_u
        if
          local.get 2
          i32.const 32
          i32.sub
          local.set 2
        end
      end
      local.get 4
      local.get 2
      i32.store8
      local.get 1
      i32.const 1
      i32.add
      local.set 1
      br 0
    end
  end
  i32.const 200
  call $resp_status
  i32.const 0
  call $resp_content_type
  i32.const 0
  i32.const 10
  call $resp_write
  i32.const 1024
  local.get 0
  call $resp_write
  i32.const 16
  i32.const 11
  call $resp_write
  local.get 0
  local.set 5
  i32.const 3010
  local.set 3
  loop
    local.get 3
    i32.const 1
    i32.sub
    local.set 3
    local.get 3
    local.get 5
    i32.const 10
    i32.rem_u
    i32.const 48
    i32.add
    i32.store8
    local.get 5
    i32.const 10
    i32.div_u
    local.tee 5
    br_if 0
  end
  local.get 3
  i32.const 3010
  local.get 3
  i32.sub
  call $resp_write
  i32.const 32
  i32.const 1
  call $resp_write
  i32.const 0
  end
  """


def make(field=2, prefix=b'{"upper":"'):
    assert len(prefix) == 10
    m = Module(memory_pages=1)
    m.import_func("req_field", 3, 1)
    m.import_func("resp_status", 1, 0)
    m.import_func("resp_content_type", 1, 0)
    m.import_func("resp_write", 2, 0)
    m.data += [(0, prefix), (16, b'","length":'), (32, b'}')]
    m.func("handle", 0, 1, 6, ASM.replace("{FIELD}", str(field)), export="handle")
    return m.build()


if __name__ == "__main__":
    open(os.path.join(os.path.dirname(__file__), "app.wasm"), "wb").write(make())
