set -euo pipefail

EC=main/ethernet.c
MC=main/main.c

cp "$EC" "$EC.bak.$(date +%s)"
cp "$MC" "$MC.bak.$(date +%s)"

# 1) Include giusto per la default netif (dichiara esp_netif_create_default_eth_netif)
grep -q '#include "esp_netif_defaults.h"' "$EC" || \
  sed -i '' '1i\
#include "esp_netif_defaults.h"
' "$EC"

# 2) Shim per ETH_CMD_G_LINK (alcune versioni lo chiamano ETH_CMD_G_LINK_STATUS)
awk 'BEGIN{ins=0}
{
  print $0
  if (!ins && $0 ~ /#include[[:space:]]*"esp_eth\.h"/) {
    print "";
    print "#ifndef ETH_CMD_G_LINK";
    print "  #ifdef ETH_CMD_G_LINK_STATUS";
    print "    #define ETH_CMD_G_LINK ETH_CMD_G_LINK_STATUS";
    print "  #endif";
    print "#endif";
    print "";
    ins=1;
  }
}' "$EC" > "$EC.tmp" && mv "$EC.tmp" "$EC"

# 3) Se c’è la funzione di dump link, ma main.c la chiama senza prototipo, per sbloccare commento il loop debug
#    (era solo diagnostica; puoi riattivarlo dopo aggiungendo il prototipo in un ethernet.h)
perl -0777 -pe 's/\n\s*for\s*\(int i\s*=\s*0; i\s*<\s*10; \+\+i\)\s*\{\s*eth_dump_link_once\(\);\s*vTaskDelay\(pdMS_TO_TICKS\(2000\)\);\s*\}\n/\n\/\/ [debug disattivato] loop dump link rimosso per build pulita\n/s' -i '' "$MC" || true

echo "[fix] Applico build…"
idf.py build
