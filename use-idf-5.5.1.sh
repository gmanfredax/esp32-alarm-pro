#!/usr/bin/env bash
# Setup ESP-IDF 5.5.1 su macOS con Python 3.13/3.12/3.11 (preferenza in quest'ordine)

set -euo pipefail

IDF_VERSION="5.5.1"
IDF_DIR="$HOME/esp/v${IDF_VERSION}/esp-idf"

# 1) Scegli Python migliore disponibile
choose_python() {
  for bin in python3.13 python3.12 python3.11 python3; do
    if command -v "$bin" >/dev/null 2>&1; then
      # Verifica che sia >= 3.9 (requisito minimo IDF 5.5)
      ver=$("$bin" - <<'PY'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}")
PY
)
      major=${ver%%.*}; minor=${ver#*.}
      if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 9 ]; }; then
        echo "$bin"; return 0
      fi
    fi
  done
  echo "Errore: serve Python >= 3.9 (consigliato 3.13/3.12). Installa con homebrew: 'brew install python@3.13'." >&2
  exit 1
}
PYBIN="$(choose_python)"

# 2) Prepara ESP-IDF v5.5.1 (clona se manca)
if [ ! -d "$IDF_DIR" ]; then
  mkdir -p "$(dirname "$IDF_DIR")"
  git clone -b "v${IDF_VERSION}" --recursive https://github.com/espressif/esp-idf.git "$IDF_DIR"
else
  # Allinea al tag esatto e submodules
  git -C "$IDF_DIR" fetch --tags
  git -C "$IDF_DIR" checkout "v${IDF_VERSION}"
  git -C "$IDF_DIR" submodule update --init --recursive
fi

# 3) Crea/aggiorna l’ambiente Python gestito da IDF
# (verrà posizionato in ~/.espressif/python_env/idf5.5_py3.xx_env)
"$PYBIN" "$IDF_DIR/tools/idf_tools.py" install-python-env

# (opzionale ma utile) assicura toolchain aggiornata per il target classico esp32
"$PYBIN" "$IDF_DIR/tools/idf_tools.py" install --targets=esp32

# 4) Esporta le variabili d’ambiente di ESP-IDF
#    (attiva anche il venv corretto creato da idf_tools.py)
# shellcheck disable=SC1090
source "$IDF_DIR/export.sh"

echo "✅ Ambiente ESP-IDF ${IDF_VERSION} pronto con $(python --version). Usa 'idf.py' da qui."

