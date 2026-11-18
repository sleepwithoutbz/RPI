#!/usr/bin/env python3
import argparse
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


LLVM_DIS = "/usr/lib/llvm-15/bin/llvm-dis"


SCHEMA = """
CREATE TABLE IF NOT EXISTS bc_files (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL,
    mtime_epoch INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    linkage TEXT NOT NULL,
    is_definition INTEGER NOT NULL,
    bc_file_id INTEGER NOT NULL,
    UNIQUE(name, is_definition, bc_file_id),
    FOREIGN KEY (bc_file_id) REFERENCES bc_files(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE INDEX IF NOT EXISTS idx_functions_name_def ON functions(name, is_definition);
"""


def iter_bc_files(root: Path):
    for path in root.rglob("*.bc"):
        if path.name.endswith(".mod.bc"):
            continue
        if "/vdso/" in str(path):
            continue
        yield path


def llvm_dis_text(path: Path) -> str:
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
        line = line.strip()
        if line.startswith("define "):
            at = line.find("@")
            if at < 0:
                continue
            end = line.find("(", at)
            if end < 0:
                continue
            name = line[at + 1:end]
            linkage = "define"
            yield (name, linkage, 1)
        elif line.startswith("declare "):
            at = line.find("@")
            if at < 0:
                continue
            end = line.find("(", at)
            if end < 0:
                continue
            name = line[at + 1:end]
            linkage = "declare"
            yield (name, linkage, 0)


def upsert_bc(conn: sqlite3.Connection, path: Path):
    st = path.stat()
    conn.execute(
        """
        INSERT INTO bc_files(path, size_bytes, mtime_epoch)
        VALUES(?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
            size_bytes=excluded.size_bytes,
            mtime_epoch=excluded.mtime_epoch
        """,
        (str(path), st.st_size, int(st.st_mtime)),
    )
    row = conn.execute("SELECT id FROM bc_files WHERE path = ?", (str(path),)).fetchone()
    return row[0]


def rebuild_functions_for_bc(conn: sqlite3.Connection, bc_file_id: int, funcs):
    conn.execute("DELETE FROM functions WHERE bc_file_id = ?", (bc_file_id,))
    conn.executemany(
        "INSERT INTO functions(name, linkage, is_definition, bc_file_id) VALUES(?, ?, ?, ?)",
        [(name, linkage, is_def, bc_file_id) for name, linkage, is_def in funcs],
    )


def build_index(root: Path, db_path: Path):
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA)

    scanned = 0
    broken = 0
    for bc in iter_bc_files(root):
        scanned += 1
        try:
            ir_text = llvm_dis_text(bc)
        except RuntimeError as exc:
            broken += 1
            print(f"[build_bc_func_index] skip broken bc: {bc}", flush=True)
            continue
        bc_id = upsert_bc(conn, bc)
        funcs = list(extract_functions(ir_text))
        rebuild_functions_for_bc(conn, bc_id, funcs)
        if scanned % 200 == 0:
            conn.commit()
            print(f"[build_bc_func_index] scanned {scanned} bc files, broken={broken}", flush=True)

    conn.commit()
    defs = conn.execute("SELECT COUNT(*) FROM functions WHERE is_definition = 1").fetchone()[0]
    decls = conn.execute("SELECT COUNT(*) FROM functions WHERE is_definition = 0").fetchone()[0]
    files = conn.execute("SELECT COUNT(*) FROM bc_files").fetchone()[0]
    conn.close()
    print(f"[build_bc_func_index] done: files={files} defs={defs} decls={decls} broken={broken}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bc-root", required=True, help="root directory containing single .bc files")
    ap.add_argument("--db", required=True, help="sqlite output path")
    args = ap.parse_args()

    root = Path(args.bc_root).resolve()
    db_path = Path(args.db).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if not root.exists():
        print(f"bc root does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    build_index(root, db_path)


if __name__ == "__main__":
    main()
