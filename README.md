# Chain of Custody Tracker (Tamper-Evident)

A lightweight, **hash-chained** chain-of-custody logger for DFIR training.  
Records case init, evidence intake (with SHA-256), transfers, and exports MD/CSV reports.  
Each record includes a `record_hash` computed over its content and the previous record’s hash → **tamper-evident**.

> For **training and authorized use only**. This demonstrates custody practices; not a legal substitute for agency systems.

## Usage
```bash
# 1) create a case
python3 custody.py init CASE123 --owner "Edward Huber"

# 2) add evidence (hashes file)
python3 custody.py add-evidence CASE123 --path ~/disk.img --desc "Seized disk image" --who "Edward Huber"

# 3) log a transfer
python3 custody.py transfer CASE123 --item 2ab3c4d5 --from "Edward Huber" --to "Lab Intake" --note "Locker A" --who "Edward Huber"

# 4) export report
python3 custody.py export CASE123 --format md
python3 custody.py export CASE123 --format csv

# 5) verify chain integrity
python3 custody.py verify CASE123
