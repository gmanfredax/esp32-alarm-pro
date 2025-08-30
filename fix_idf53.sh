set -euo pipefail

file1="main/netmon.c"
file2="main/mqtt_client.c"

# Backup con timestamp
cp "$file1" "$file1.bak.$(date +%s)"
cp "$file2" "$file2.bak.$(date +%s)"

# 1) IDF 5.3: esp_netif_dns_info_t usa 'ip' non 'addr'
#   sostituisce TUTTE le occorrenze dns.addr (qualsiasi sottocampo) -> dns.ip
perl -0777 -pe 's/\bdns\.addr\b/dns.ip/g' -i '' "$file1"

# 2) Eventi Ethernet: servono le definizioni da esp_eth.h
if ! grep -q '#include "esp_eth.h"' "$file2"; then
  awk '{
    print $0
    if ($0 ~ /#include[[:space:]]*\"esp_event\.h\"/ && !inserted) {
      print "#include \"esp_eth.h\""
      inserted=1
    }
  } END {
    if (!inserted) print "#include \"esp_eth.h\""
  }' "$file2" > "$file2.tmp" && mv "$file2.tmp" "$file2"
fi

echo "[fix-idf53] Modifiche applicate. Avvio build…"
idf.py build
