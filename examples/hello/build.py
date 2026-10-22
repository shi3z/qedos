#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
from qswasm import Module

BODY = b'{"message":"Hello from QEDOS"}'
m = Module(memory_pages=1)
m.import_func("resp_status", 1, 0)
m.import_func("resp_content_type", 1, 0)
m.import_func("resp_write", 2, 0)
m.data.append((0, BODY))
m.func("handle", 0, 1, 0, f"""
i32.const 200
call $resp_status
i32.const 0          ;; application/json
call $resp_content_type
i32.const 0
i32.const {len(BODY)}
call $resp_write
i32.const 0
end
""", export="handle")
open(os.path.join(os.path.dirname(__file__), "app.wasm"), "wb").write(m.build())
