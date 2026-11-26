"""Offline M5 parity: reference selftest plus exact rounded score comparison.

The lesson is loaded only in this test process, never by production Rust code.
No models, real history, browser profile or network are used.
"""
import copy
import json
import math
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "web3lesson"))


def no_network(*args, **kwargs):
    raise AssertionError("math parity must stay offline")


urllib.request.urlopen = no_network
with tempfile.TemporaryDirectory(prefix="nymwrap-math-") as temporary:
    os.environ["ANTI_HOME"] = temporary
    reference = runpy.run_path(str(ROOT / "web3lesson/anti.py"))
    assert reference["selftest"]() == 0
    angles = {"x1": 0.0, "x2": 0.1, "y1": 1.47, "y2": 1.57,
              "s1": 0.05, "s2": 0.5, "s3": 1.0, "s4": 1.5}

    def embed(texts):
        return [[math.cos(angles[t]), math.sin(angles[t])] for t in texts]

    roadmap = {"persona": {"interests": ["x1", "x2"]},
               "anti_persona": {"interests": ["y1"], "interests_outside_work": ["y2"]},
               "stages": [{"search_queries": [s]} for s in ["s1", "s2", "s3", "s4"]]}
    bad = copy.deepcopy(roadmap)
    bad["stages"][2]["search_queries"] = ["s1"]
    cases = [(roadmap, 4), (bad, 4), (roadmap, 5)]
    rust_input = [{"persona": embed(["x1", "x2"]), "cover": embed(["y1", "y2"]),
                   "stages": [embed(s["search_queries"]) for s in rm["stages"]], "expected": n}
                  for rm, n in cases]
    env = {**os.environ, "CARGO_BUILD_JOBS": "4"}
    result = subprocess.run(["cargo", "run", "--quiet", "--locked", "-p", "nw-drift",
                             "--example", "math_reference"], cwd=ROOT, env=env,
                            input=json.dumps(rust_input), text=True, capture_output=True, check=True)
    actual = json.loads(result.stdout)
    assert actual["projections"] == [0.0, 1.0, 0.5]
    for (rm, n), rust in zip(cases, actual["scores"], strict=True):
        expected = reference["score"](rm, emb=embed, n=n)
        expected["positions"] = expected.pop("pos")
        for key, value in rust.items():
            assert expected[key] == value, (key, expected[key], value)
    print("M5: Rust axis/score matches anti.py selftest (valid, backslide, stage count)")
