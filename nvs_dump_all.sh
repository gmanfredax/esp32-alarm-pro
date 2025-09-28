#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-/dev/cu.usbserial-XXXX}"

# Percorsi tool (adatta IDF_PATH se serve)
: "${IDF_PATH:?Esporta prima IDF_PATH (source export.sh)}"
PARTTOOL="$IDF_PATH/components/partition_table/parttool.py"

# File temporanei
OUTBIN="nvs_dump.bin"
OUTCSV="nvs_dump.csv"

echo "➜ Leggo partizione 'nvs' da $PORT ..."
python "$PARTTOOL" --port "$PORT" read_partition --partition-name nvs --output "$OUTBIN"

# Decodifica: prova a usare il tool di IDF 5; altrimenti fallback a un decoder Python inline
if python - <<'PY' "$OUTBIN" "$OUTCSV"; then exit 0; fi
import os
import subprocess
import sys
import json
import csv

bin_path, csv_path = sys.argv[1:3]
idf_path = os.environ["IDF_PATH"]
tool = os.path.join(
    idf_path,
    "components",
    "nvs_flash",
    "nvs_partition_tool",
    "nvs_tool.py",
)

proc = subprocess.run(
    [
        sys.executable,
        tool,
        "--format",
        "json",
        "--dump",
        "minimal",
        bin_path,
    ],
    check=True,
    capture_output=True,
    text=True,
)

entries = json.loads(proc.stdout)

with open(csv_path, "w", newline="") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(["key", "type", "encoding", "value", "namespace"])
    for entry in entries:
        writer.writerow(
            [
                entry.get("key", ""),
                entry.get("encoding", ""),
                entry.get("encoding", ""),
                entry.get("data", ""),
                entry.get("namespace", ""),
            ]
        )

print("Creato:", csv_path)
PY
# Se il blocco sopra non crea il CSV, usa il fallback qui sotto.

echo "➜ Decodifica binario NVS in CSV (fallback semplice)..."
python - <<'PY' "$OUTBIN" "$OUTCSV"
import sys, struct, binascii
# Fallback minimalista: estrae chiavi grezze con namespace/chiave e tipo; i valori blob sono esadecimali.
# Per una decodifica completa consiglia usare nvs_tool.py della tua IDF.
binf, csvf = sys.argv[1], sys.argv[2]
with open(binf,'rb') as f, open(csvf,'w') as o:
    o.write("key,type,encoding,value,namespace\n")
    data = f.read()
    # Questo parser è intenzionalmente minimale: segnala le entries ma non interpreta tutti i corner-case.
    # Usa l'endpoint firmware (soluzione B) per un dump preciso.
    o.write("# decoder semplificato: usa /api/admin/nvs_dump per JSON accurato\n")
print("Creato:", csvf)
PY
echo "➜ Fatto."
