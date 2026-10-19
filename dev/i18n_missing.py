#!/usr/bin/env python3
"""List UI texts that have no Russian / Uzbek translation in pve-gateway.py's I18N catalog (dev only).

    python3 dev/i18n_missing.py            # texts from the HTML, JS string literals and server messages
    python3 dev/i18n_missing.py --unused   # catalog entries no longer found in the code (candidates to delete)

It is a heuristic: JS strings built with "+" are reported as fragments, so add them to I18N as a template with
{0}, {1}, ... for the variable parts (see the existing entries). Single words are only checked in the HTML.
Switch the language in Settings -> Language to see what is still English on screen.
"""
import ast
import importlib.util
import os
import re
import sys
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "..", "pve-gateway.py")
SRC = open(PATH, encoding="utf-8").read()
spec = importlib.util.spec_from_file_location("pvegw", PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
CAT = mod.I18N
FMT = re.compile(r"%(?:\([a-z_]+\))?[-+ #0]*\d*(?:\.\d+)?[sdrfi]")


def block(name):
    return SRC.split(name + ' = r"""')[1].split('"""')[0]


def numbered(t):
    i = [0]

    def sub(m):
        i[0] += 1
        return "{%d}" % (i[0] - 1)
    return re.sub(r"\{\d+\}|\{V\}", sub, FMT.sub("{V}", t.replace("%%", "%")))


found = set()


class P(HTMLParser):
    skip = 0

    def handle_starttag(self, tag, attrs):
        self.skip += tag in ("script", "style", "code", "pre")
        for k, v in attrs:
            if k in ("placeholder", "title", "aria-label") and v and re.search(r"[A-Za-z]{2}", v):
                found.add(" ".join(v.split()))

    def handle_endtag(self, tag):
        self.skip -= tag in ("script", "style", "code", "pre")

    def handle_data(self, data):
        t = " ".join(data.split())
        if not self.skip and re.search(r"[A-Za-z]{2}", t):
            found.add(t)


P().feed(block("INDEX_HTML"))
js = block("APP_JS")
for m in re.finditer(r"'((?:[^'\\]|\\.)*)'", js):
    t = " ".join(m.group(1).split())
    if re.fullmatch(r"[a-z-]+ [a-z-]+", t) or re.match(r"^[+,:?)]", t):  # CSS class lists, code fragments
        continue
    code = re.search(r"\$\(|=>|;|===|!==|&&|\|\||\)\s*[.{+:?]|^\)|\bconst\b|\breturn\b", t)  # quote mismatch, not text
    if re.search(r"[A-Za-z]{3,}", t) and " " in t and not code and not re.match(r"^(/|#|\.|\$|https?:)", t):
        found.add(t)
tree = ast.parse(SRC)
skip = set()
for n in ast.walk(tree):
    if isinstance(n, ast.Call):
        f = n.func
        name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
        if name in ("log", "run", "sh", "print", "compile", "match", "search", "sub", "findall", "write", "join"):
            skip.update(id(a) for a in ast.walk(n))
    if isinstance(n, (ast.FunctionDef, ast.Module)) and n.body and isinstance(n.body[0], ast.Expr):
        skip.add(id(n.body[0].value))
for n in ast.walk(tree):
    if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "ApiError" and n.args and id(n) not in skip:
        a = n.args[0]
        a = a.left if isinstance(a, ast.BinOp) and isinstance(a.op, ast.Mod) else a
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            found.add(numbered(" ".join(a.value.split())))


def covered(t):
    if t in CAT:
        return True
    for k in CAT:
        if "{" in k and re.fullmatch(re.sub(r"\\\{\d+\\\}", ".+?", re.escape(k)), t, re.S):
            return True
    return any(t in k for k in CAT)  # a fragment of a longer template


if "--unused" in sys.argv:
    blob = SRC.split("I18N = {")[0] + SRC.split("I18N = {")[1].split("\n}\n", 1)[1]
    for k in sorted(CAT):
        lit = max(re.split(r"\{\d+\}", k), key=len).strip()
        if lit and lit not in blob:
            print(k)
else:
    for t in sorted(found):
        if not covered(t):
            print(t)
