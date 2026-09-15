#!/usr/bin/env python3
"""学习式前缀规则的回归测试。

要点：
  - 只学该学的（构建/测试/lint 类头），不该学的一条都不学
  - 见两次才升级
  - 升级后变体也能放行
  - deny 永远优先于学到的规则
用法: python3 test-learn.py
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HOOK = Path(__file__).resolve().parent / "review-command.py"
LEARNED = Path(tempfile.mkdtemp()) / "learned.json"
os.environ["ZCODE_HOOK_LEARNED"] = str(LEARNED)   # 必须在 import 之前设

spec = importlib.util.spec_from_file_location("rc", HOOK)
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)

fail = 0


def check(label, ok, detail=""):
    global fail
    if not ok:
        fail += 1
    print(f"  {'OK ' if ok else 'FAIL'} {label}{'  ' + detail if detail else ''}")


def cands(cmd):
    p = rc.load_policy()
    return rc.learn_candidates(cmd, p["learn"], p)


def decide(cmd):
    return rc.decide(cmd, rc.load_policy())[0]


print("=== 1) 该学的能抽出候选 ===")
for cmd, want in [
    ("cargo test", ["cargo test"]),
    ("cargo test --lib", ["cargo test"]),
    ('cd /tmp/proj && cargo test --all && pytest -q', ["cargo test", "pytest"]),
    ("npm run build", ["npm run build"]),
    ("git commit -m 'wip'", ["git commit"]),
    ("pytest -k foo", ["pytest"]),
]:
    got = [" ".join(c) for c in cands(cmd)]
    check(f"{cmd!r} -> {got}", got == want, f"期望 {want}")

print("\n=== 2) 不该学的一条都不能学 ===")
for cmd, why in [
    ("python3 -c 'print(1)'", "解释器"),
    ("/usr/bin/python3 script.py", "绝对路径"),
    ("./deploy.sh --prod", "./ 脚本"),
    ("node build.js", "解释器"),
    ("cargo install cargo-watch", "install 被禁"),
    ("git push origin main", "push 被禁"),
    ("npm install lodash", "install 被禁"),
    ("pytest -q > out.txt", "重定向"),
    ("pytest $(ls)", "命令替换"),
    ("pytest -q &", "后台符"),
    ("rm -rf /tmp/x", "头不在名单"),
    ("make install", "install 被禁"),
    ("git clean -fdx", "clean 被禁"),
    ("pip install -e .", "头不在名单"),
]:
    got = cands(cmd)
    check(f"{cmd!r} ({why})", got == [], f"实得 {got}")

print("\n=== 3) 见两次才升级 ===")
rc.learn_observe("cargo test --lib", rc.load_policy()["learn"], rc.load_policy())
check("第 1 次后仍不放行", decide("cargo test") == "ask", decide("cargo test"))
check("第 1 次后进入候选", bool(rc.learn_load(rc.load_policy()["learn"]).get("pending")))
rc.learn_observe("cargo test --all", rc.load_policy()["learn"], rc.load_policy())
check("第 2 次后升级放行", decide("cargo test") == "allow", decide("cargo test"))
check("变体也放行", decide("cargo test --lib --release") == "allow", decide("cargo test --lib --release"))
check("复合命令里也放行", decide("cd /tmp && cargo test") == "allow", decide("cd /tmp && cargo test"))
check("不相关命令仍走人工", decide("npm install x") == "ask", decide("npm install x"))

print("\n=== 4) deny 优先于学到的规则 ===")
check("cargo test && rm -rf /", decide("cargo test && rm -rf /") == "deny", decide("cargo test && rm -rf /"))
check("cargo test 前缀不该放过 sudo", decide("cargo test && sudo rm x") == "deny", decide("cargo test && sudo rm x"))
rc.learn_observe("git commit -m x", rc.load_policy()["learn"], rc.load_policy())
rc.learn_observe("git commit -m y", rc.load_policy()["learn"], rc.load_policy())
check("git commit 学成后放行", decide("git commit -m z") == "allow", decide("git commit -m z"))
check("但 git push --force 仍然 deny", decide("git commit -m z && git push --force") == "deny",
      decide("git commit -m z && git push --force"))

print("\n=== 5) CLI: --learned / --forget ===")
env = {**os.environ, "ZCODE_HOOK_LEARNED": str(LEARNED)}
out = subprocess.run([sys.executable, str(HOOK), "--learned"], capture_output=True, text=True, env=env).stdout
check("--learned 列出规则", "cargo test" in out, out.strip().splitlines()[4] if len(out.splitlines()) > 4 else "")
forget = subprocess.run([sys.executable, str(HOOK), "--forget", "cargo test"], capture_output=True, text=True, env=env)
check("--forget 删除", "已删除" in forget.stdout, forget.stdout.strip())
check("删除后回到人工", decide("cargo test") == "ask", decide("cargo test"))

print(f"\n{'ALL PASS' if fail == 0 else str(fail) + ' FAILED'}")
sys.exit(1 if fail else 0)
