#!/usr/bin/env python3
"""GET handler: echoes the URL query string (?a=b) uppercased as {"query":"...","length":N}."""
import importlib.util, os
here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("echo_build", os.path.join(here, "..", "json-echo", "build.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
open(os.path.join(here, "app.wasm"), "wb").write(mod.make(field=1, prefix=b'{"query":"'))
