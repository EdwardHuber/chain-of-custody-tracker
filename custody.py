#!/usr/bin/env python3
"""
Chain of Custody Tracker (tamper-evident)
Focus: Evidence integrity and transfer logging for DFIR training

Subcommands:
  init <CASE_ID>
  add-evidence <CASE_ID> --path PATH [--desc "desc"]
  transfer <CASE_ID> --item ITEM_ID --from FROM --to TO [--note "note"]
  export <CASE_ID> --format md|csv
  verify <CASE_ID>

All data stored under cases/<CASE_ID>/:
  - chain.jsonl     (append-only, hash-chained)
  - evidence/       (optional copies, if you choose to store them here)
  - exports/        (reports)

Usage examples:
  python3 custody.py init CASE123 --owner "Edward Huber"
  python3 custody.py add-evidence CASE123 --path ~/disk.img --desc "Seized disk image" --who "Edward Huber"
  python3 custody.py transfer CASE123 --item 2ab3c4d5 --from "Edward Huber" --to "Lab Intake" --note "Locker A" --who "Edward Huber"
  python3 custody.py export CASE123 --format md
  python3 custody.py verify CASE123
"""
import argparse, hashlib, json, os, pathlib, time, csv
from datetime import datetime

ROOT = pathlib.Path("cases")

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def hash_record(rec, prev_hash):
    # rec should include prev_hash when hashed
    base = json.dumps(rec, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(prev_hash.encode("utf-8") + base).hexdigest()

def case_dir(case_id): return ROOT / case_id
def chain_path(case_id): return case_dir(case_id) / "chain.jsonl"

def read_chain(case_id):
    p = chain_path(case_id)
    if not p.exists(): return []
    items=[]
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            items.append(json.loads(line))
    return items

def append_record(case_id, rec):
    cdir = case_dir(case_id)
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir/"evidence").mkdir(exist_ok=True)
    (cdir/"exports").mkdir(exist_ok=True)

    chain = read_chain(case_id)
    prev = chain[-1]["record_hash"] if chain else "0"*64

    # include prev_hash in the material being hashed
    rec["prev_hash"] = prev
    rec["record_hash"] = hash_record(rec, prev)

    with open(chain_path(case_id), "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec["record_hash"]

def cmd_init(args):
    rec = {
        "type":"init",
        "case_id": args.case_id,
        "ts": datetime.utcnow().isoformat()+"Z",
        "who": args.owner
    }
    h = append_record(args.case_id, rec)
    print(f"[✓] Initialized case {args.case_id} • record {h[:8]}")

def cmd_add_evidence(args):
    p = pathlib.Path(args.path).expanduser().resolve()
    if not p.exists():
        raise SystemExit(f"[!] Not found: {p}")
    file_hash = sha256_file(p)
    item_id = args.item_id or file_hash[:8]
    rec = {
        "type":"add_evidence",
        "case_id": args.case_id,
        "item_id": item_id,
        "path": str(p),
        "sha256": file_hash,
        "desc": args.desc or "",
        "ts": datetime.utcnow().isoformat()+"Z",
        "who": args.who
    }
    h = append_record(args.case_id, rec)
    print(f"[✓] Added evidence {item_id} (sha256={file_hash[:12]}...) • record {h[:8]}")

def cmd_transfer(args):
    rec = {
        "type":"transfer",
        "case_id": args.case_id,
        "item_id": args.item_id,
        "from": args.from_person,
        "to": args.to_person,
        "note": args.note or "",
        "ts": datetime.utcnow().isoformat()+"Z",
        "who": args.who
    }
    h = append_record(args.case_id, rec)
    print(f"[✓] Transfer logged for item {args.item_id} • record {h[:8]}")

def cmd_export(args):
    chain = read_chain(args.case_id)
    ed = case_dir(args.case_id)/"exports"
    ed.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if args.format == "md":
        out = ed/f"chain_{stamp}.md"
        lines = [f"# Chain of Custody — {args.case_id}", ""]
        for r in chain:
            lines += [
                f"**{r['type']}**  ",
                f"- Time: `{r['ts']}`  ",
                f"- Who: `{r.get('who','')}`  ",
                *( [f"- Item: `{r['item_id']}`  "] if 'item_id' in r else [] ),
                *( [f"- From: `{r['from']}`  - To: `{r['to']}`  "] if r.get('type')=='transfer' else [] ),
                *( [f"- Path: `{r['path']}`  ", f"- sha256: `{r['sha256']}`  "] if r.get('type')=='add_evidence' else [] ),
                *( [f"- Note: {r['note']}  "] if r.get('note') else [] ),
                f"- Record: `{r['record_hash']}` (prev `{r['prev_hash']}`)", ""
            ]
        out.write_text("\n".join(lines), encoding="utf-8")
        print(f"[✓] Wrote {out}")
    elif args.format == "csv":
        out = ed*f"/chain_{stamp}.csv"
        with open(out, "w", newline="", encoding="utf-8") as f:
            w=csv.writer(f)
            w.writerow(["type","ts","who","item_id","from","to","path","sha256","note","record_hash","prev_hash"])
            for r in chain:
                w.writerow([r.get("type",""),r.get("ts",""),r.get("who",""),r.get("item_id",""),
                            r.get("from",""),r.get("to",""),r.get("path",""),r.get("sha256",""),
                            r.get("note",""),r.get("record_hash",""),r.get("prev_hash","")])
        print(f"[✓] Wrote {out}")
    else:
        raise SystemExit("[!] Use --format md|csv")

def cmd_verify(args):
    chain = read_chain(args.case_id)
    # Verify prev links and record hashes
    prev = "0"*64
    ok = True
    for i, r in enumerate(chain):
        # Check the prev link is what we expect
        if r.get("prev_hash","") != prev:
            print(f"[!] Tamper suspected at record #{i}: prev_hash mismatch")
            ok = False
            break
        # Recompute record_hash using the same fields as when created (including prev_hash)
        material = {k:v for k,v in r.items() if k != "record_hash"}
        recomputed = hash_record(material, material["prev_hash"])
        if r.get("record_hash","") != recomputed:
            print(f"[!] Tamper suspected at record #{i}: record_hash mismatch")
            ok = False
            break
        prev = r["record_hash"]
    print("[✓] Chain verified OK" if ok else "[X] Chain failed verification")
    if not ok:
        raise SystemExit(1)

def main():
    ap = argparse.ArgumentParser(description="Chain of Custody Tracker (tamper-evident)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init")
    sp.add_argument("case_id")
    sp.add_argument("--owner", default="unknown")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("add-evidence")
    sp.add_argument("case_id")
    sp.add_argument("--path", required=True)
    sp.add_argument("--desc", default="")
    sp.add_argument("--item-id", dest="item_id", default=None)
    sp.add_argument("--who", default="unknown")
    sp.set_defaults(func=cmd_add_evidence)

    sp = sub.add_parser("transfer")
    sp.add_argument("case_id")
    sp.add_argument("--item", dest="item_id", required=True)
    sp.add_argument("--from", dest="from_person", required=True)
    sp.add_argument("--to", dest="to_person", required=True)
    sp.add_argument("--note", default="")
    sp.add_argument("--who", default="unknown")
    sp.set_defaults(func=cmd_transfer)

    sp = sub.add_parser("export")
    sp.add_argument("case_id")
    sp.add_argument("--format", choices=["md","csv"], required=True)
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("verify")
    sp.add_argument("case_id")
    sp.set_defaults(func=cmd_verify)

    args = ap.parse_args()
    ROOT.mkdir(exist_ok=True)
    args.func(args)

if __name__ == "__main__":
    main()
