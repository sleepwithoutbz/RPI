#!/usr/bin/env python3
import argparse
import json
import os
import re
import shlex
import sqlite3
import subprocess
from collections import deque
from pathlib import Path


LLVM_DIS = "/usr/lib/llvm-15/bin/llvm-dis"
LLVM_LINK = "/usr/lib/llvm-15/bin/llvm-link"
LLVM_AS = "/usr/lib/llvm-15/bin/llvm-as"


IGNORE_CALLEE_PREFIXES = (
    "llvm.",
    "__asan_",
    "__ubsan_",
    "__kasan_",
    "__SCT__",
    "__traceiter_",
    "__tracepoint_",
    "__pfx_",
)

IGNORE_CALLEES = {
    "__fentry__",
    "__mcount",
}

IGNORE_BC_SUBSTRINGS = (
    "/arch/x86/boot/",
    "/boot/compressed/",
    "/realmode/",
    "/vdso/",
)

STRIP_FLAG_PREFIXES = (
    "-fsanitize=",
    "-fsanitize-coverage=",
    "-mllvm",
)

STRIP_EXACT_FLAGS = {
    "-pg",
    "-mfentry",
}


def parse_entry_config(path: Path):
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] != "*":
            return parts[0]
    raise RuntimeError(f"no entry function found in {path}")


def defined_bcs_for(conn: sqlite3.Connection, func_name: str):
    rows = conn.execute(
        """
        select distinct bc_files.path
        from functions
        join bc_files on functions.bc_file_id = bc_files.id
        where functions.name = ? and functions.is_definition = 1
        order by bc_files.path
        """,
        (func_name,),
    ).fetchall()
    return [row[0] for row in rows]


def load_definition_index(conn: sqlite3.Connection):
    idx = {}
    rows = conn.execute(
        """
        select functions.name, bc_files.path
        from functions
        join bc_files on functions.bc_file_id = bc_files.id
        where functions.is_definition = 1
        order by functions.name, bc_files.path
        """
    ).fetchall()
    for name, path in rows:
        if not Path(path).exists():
            continue
        idx.setdefault(name, []).append(path)
    return idx


def register_materialized_bc(def_index: dict, path: Path, ir_text: str):
    funcs = list(extract_functions(ir_text))
    for name, _, is_def in funcs:
        if is_def:
            defs = def_index.setdefault(name, [])
            p = str(path)
            if p not in defs:
                defs.append(p)


def should_ignore_bc_path(path: Path) -> bool:
    s = str(path)
    return any(part in s for part in IGNORE_BC_SUBSTRINGS)


def llvm_dis_to_text(path: Path) -> str:
    proc = subprocess.run(
        [LLVM_DIS, str(path), "-o", "-"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"llvm-dis failed for {path}: {proc.stderr.strip()}")
    return proc.stdout


def extract_functions(ir_text: str):
    for line in ir_text.splitlines():
        s = line.strip()
        if s.startswith("define "):
            at = s.find("@")
            end = s.find("(", at)
            if at >= 0 and end > at:
                yield (s[at + 1:end], "define", 1)
        elif s.startswith("declare "):
            at = s.find("@")
            end = s.find("(", at)
            if at >= 0 and end > at:
                yield (s[at + 1:end], "declare", 0)


def extract_direct_calls(ir_text: str, func_name: str):
    lines = ir_text.splitlines()
    inside = False
    brace_depth = 0
    calls = set()
    call_re = re.compile(r"\b(?:tail\s+|musttail\s+|notail\s+)?call\b[^@]*@([A-Za-z0-9_.$]+)\(")
    for line in lines:
        s = line.strip()
        if not inside:
            if s.startswith("define ") and f"@{func_name}(" in s:
                inside = True
                brace_depth = s.count("{") - s.count("}")
            continue
        brace_depth += s.count("{") - s.count("}")
        if brace_depth <= 0:
            inside = False
            continue
        m = call_re.search(s)
        if not m:
            continue
        callee = m.group(1)
        if callee == func_name:
            continue
        if callee in IGNORE_CALLEES:
            continue
        if any(callee.startswith(prefix) for prefix in IGNORE_CALLEE_PREFIXES):
            continue
        calls.add(callee)
    return calls


def find_candidate_sources(bc_root: Path, func_name: str):
    proc = subprocess.run(
        ["rg", "-l", "-g", "*.c", rf"\b{re.escape(func_name)}\s*\(", str(bc_root)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr.strip())
    candidates = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        src = Path(line.strip())
        try:
            text = src.read_text(errors="ignore")
        except Exception:
            continue
        if source_defines_function(text, func_name):
            candidates.append(src)
    return candidates


def skip_ws_and_comments(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        if text[i].isspace():
            i += 1
            continue
        if text.startswith("//", i):
            nl = text.find("\n", i + 2)
            return n if nl < 0 else nl + 1
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            return n if end < 0 else end + 2
        break
    return i


def skip_balanced(text: str, i: int, open_ch: str, close_ch: str) -> int:
    n = len(text)
    depth = 0
    while i < n:
        ch = text[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        elif ch in ("'", '"'):
            quote = ch
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    break
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                return n
            i = end + 1
        elif text.startswith("//", i):
            nl = text.find("\n", i + 2)
            if nl < 0:
                return n
            i = nl
        i += 1
    return n


def source_defines_function(text: str, func_name: str) -> bool:
    needle = f"{func_name}("
    start = 0
    n = len(text)
    while True:
        idx = text.find(needle, start)
        if idx < 0:
            return False
        if idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            start = idx + 1
            continue
        after_args = skip_balanced(text, idx + len(func_name), "(", ")")
        if after_args >= n:
            return False
        j = skip_ws_and_comments(text, after_args)
        while j < n and (text[j].isalpha() or text[j] == "_"):
            k = j + 1
            while k < n and (text[k].isalnum() or text[k] == "_"):
                k += 1
            j = skip_ws_and_comments(text, k)
            if j < n and text[j] == "(":
                j = skip_ws_and_comments(text, skip_balanced(text, j, "(", ")"))
                continue
            break
        if j < n and text[j] == "{":
            return True
        start = idx + 1


def cmd_file_for_source(bc_root: Path, src: Path) -> Path:
    rel = src.relative_to(bc_root)
    return src.parent / f".{src.stem}.o.cmd"


def build_bc_from_cmd(bc_root: Path, cmd_file: Path, out_bc: Path):
    if out_bc.exists():
        return
    text = cmd_file.read_text()
    saved_line = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("savedcmd_") and ":=" in line:
            saved_line = line
            break
    if saved_line is None:
        raise RuntimeError(f"unexpected cmd format: {cmd_file}")
    cmd = saved_line.split(":=", 1)[1].strip()
    cmd = cmd.split(" ; ", 1)[0].strip()
    argv = shlex.split(cmd)

    filtered = []
    skip_next = False
    output_replaced = False
    out_rel = os.path.relpath(str(out_bc), str(bc_root))
    src_rel = os.path.relpath(str(cmd_file.with_name(cmd_file.name[1:-6] + ".c")), str(bc_root))
    for i, tok in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if tok == "-o":
            filtered.extend(["-o", out_rel])
            skip_next = True
            output_replaced = True
            continue
        if tok.startswith("-fpass-plugin="):
            continue
        if tok in STRIP_EXACT_FLAGS:
            continue
        if any(tok.startswith(prefix) for prefix in STRIP_FLAG_PREFIXES):
            if tok == "-mllvm":
                skip_next = True
            continue
        if tok.endswith(".c") and "/" not in tok:
            filtered.append(src_rel)
            continue
        filtered.append(tok)
    if not output_replaced:
        raise RuntimeError(f"no -o found in {cmd_file}")
    if "-emit-llvm" not in filtered:
        filtered.insert(1, "-emit-llvm")
    proc = subprocess.run(filtered, cwd=str(bc_root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip())


def materialize_missing_define(def_index: dict, func_name: str, bc_root: Path, work_dir: Path):
    cache_dir = work_dir / "materialized-bc"
    cache_dir.mkdir(parents=True, exist_ok=True)
    candidates = find_candidate_sources(bc_root, func_name)
    print(f"[build_entry_closure_bc] materialize {func_name}: candidates={len(candidates)}", flush=True)
    for src in candidates:
        cmd_file = cmd_file_for_source(bc_root, src)
        if not cmd_file.exists():
            print(f"[build_entry_closure_bc] skip no cmd: {src}", flush=True)
            continue
        out_bc = cache_dir / src.relative_to(bc_root).with_suffix(".bc")
        out_bc.parent.mkdir(parents=True, exist_ok=True)
        try:
            build_bc_from_cmd(bc_root, cmd_file, out_bc)
            ir_text = llvm_dis_to_text(out_bc)
            register_materialized_bc(def_index, out_bc, ir_text)
            print(f"[build_entry_closure_bc] built {out_bc}", flush=True)
        except Exception as exc:
            print(f"[build_entry_closure_bc] build failed for {src}: {exc}", flush=True)
            continue
        defs = def_index.get(func_name, [])
        print(f"[build_entry_closure_bc] defs for {func_name}: {defs}", flush=True)
        if len(defs) == 1:
            return defs[0]
    return None


def module_tag_from_bc(bc: Path, bc_roots) -> str:
    for root in bc_roots:
        try:
            rel = str(bc.relative_to(root))
            return rel.replace("/", "_").removesuffix(".bc")
        except ValueError:
            continue
    return str(bc).replace("/", "_").removesuffix(".bc")


def prepare_module_bc(bc: Path, out_dir: Path, bc_roots) -> Path:
    tag = module_tag_from_bc(bc, bc_roots)
    ll = out_dir / f"{tag}.ll"
    out = out_dir / f"{tag}.bc"
    init_sym = f"{tag}__init_module"
    cleanup_sym = f"{tag}__cleanup_module"

    subprocess.run([LLVM_DIS, str(bc), "-o", str(ll)], check=True)
    text = ll.read_text()
    text = text.replace("@init_module", f"@{init_sym}")
    text = text.replace("@cleanup_module", f"@{cleanup_sym}")
    text = text.replace("__addressable_init_module", f"__addressable_{init_sym}")
    text = text.replace("__addressable_cleanup_module", f"__addressable_{cleanup_sym}")
    ll.write_text(text)
    subprocess.run([LLVM_AS, str(ll), "-o", str(out)], check=True)
    return out


def is_module_bc(bc: Path) -> bool:
    proc = subprocess.run(
        ["/usr/bin/llvm-nm-15", "--defined-only", str(bc)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return False
    return " init_module" in proc.stdout or " cleanup_module" in proc.stdout


def build_closure(conn: sqlite3.Connection, entry: str, work_dir: Path, bc_root: Path):
    def_index = load_definition_index(conn)
    entry_defs = def_index.get(entry, [])
    if len(entry_defs) != 1:
        raise RuntimeError(f"entry {entry} has {len(entry_defs)} defining bc files: {entry_defs}")

    module_linkable_dir = work_dir / "module-linkable"
    module_linkable_dir.mkdir(parents=True, exist_ok=True)
    materialized_root = work_dir / "materialized-bc"
    bc_roots = [bc_root, materialized_root]

    selected_bcs = set(entry_defs)
    queue = deque([(entry_defs[0], entry)])
    visited_funcs = set()
    resolution_log = []
    unresolved_callees = set()

    while queue:
        bc_path_str, func_name = queue.popleft()
        if (bc_path_str, func_name) in visited_funcs:
            continue
        visited_funcs.add((bc_path_str, func_name))

        ir_text = llvm_dis_to_text(Path(bc_path_str))
        callees = extract_direct_calls(ir_text, func_name)
        for callee in sorted(callees):
            if callee in unresolved_callees:
                continue
            defs = def_index.get(callee, [])
            defs = [p for p in defs if Path(p).exists()]
            if defs != def_index.get(callee, []):
                if defs:
                    def_index[callee] = defs
                else:
                    def_index.pop(callee, None)
            if len(defs) == 0:
                materialize_missing_define(def_index, callee, bc_root, work_dir)
                defs = def_index.get(callee, [])
            if len(defs) != 1:
                unresolved_callees.add(callee)
                continue
            target_bc = defs[0]
            if should_ignore_bc_path(Path(target_bc)):
                unresolved_callees.add(callee)
                continue
            if not Path(target_bc).exists():
                materialize_missing_define(def_index, callee, bc_root, work_dir)
                defs = [p for p in def_index.get(callee, []) if Path(p).exists()]
                if len(defs) != 1:
                    unresolved_callees.add(callee)
                    continue
                target_bc = defs[0]
                if should_ignore_bc_path(Path(target_bc)):
                    unresolved_callees.add(callee)
                    continue
            resolution_log.append((func_name, callee, target_bc))
            if target_bc not in selected_bcs:
                selected_bcs.add(target_bc)
            queue.append((target_bc, callee))

    prepared_inputs = []
    for bc_path_str in sorted(selected_bcs):
        bc = Path(bc_path_str)
        if is_module_bc(bc):
            prepared_inputs.append(str(prepare_module_bc(bc, module_linkable_dir, bc_roots)))
        else:
            prepared_inputs.append(str(bc))

    return prepared_inputs, resolution_log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--entry-config", required=True)
    ap.add_argument("--out-bc", required=True)
    ap.add_argument("--work-dir", required=True)
    ap.add_argument("--bc-root", required=True)
    args = ap.parse_args()

    db = Path(args.db).resolve()
    entry_config = Path(args.entry_config).resolve()
    out_bc = Path(args.out_bc).resolve()
    work_dir = Path(args.work_dir).resolve()
    bc_root = Path(args.bc_root).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    out_bc.parent.mkdir(parents=True, exist_ok=True)

    entry = parse_entry_config(entry_config)
    conn = sqlite3.connect(str(db))
    inputs, log = build_closure(conn, entry, work_dir, bc_root)
    conn.close()

    subprocess.run([LLVM_LINK, "--internalize", *inputs, "-o", str(out_bc)], check=True)

    manifest = {
        "entry": entry,
        "inputs": inputs,
        "edges": [{"caller": c, "callee": cal, "bc": bc} for c, cal, bc in log],
    }
    (work_dir / "closure_manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"[build_entry_closure_bc] entry={entry}")
    print(f"[build_entry_closure_bc] input_count={len(inputs)}")
    print(f"[build_entry_closure_bc] out_bc={out_bc}")


if __name__ == "__main__":
    main()
