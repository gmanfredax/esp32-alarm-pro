#!/bin/bash
# Script per attivare ambiente ESP-IDF 5.3.4 con Python 3.11

# Attiva il venv Python 3.11
source ~/.espressif/python_env/idf5.3_py3.11_env/bin/activate

# Esporta le variabili ESP-IDF
source ~/esp/v5.3.4/esp-idf/export.sh

# Mostra conferma
echo "✅ Ambiente ESP-IDF 5.3.4 pronto. Usa 'idf.py' da qui."

