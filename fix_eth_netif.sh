set -euo pipefail

f="main/ethernet.c"
ts=$(date +%s)
cp "$f" "$f.bak.$ts"

# 1) Assicura gli include
for inc in '#include "esp_event.h"' '#include "esp_netif.h"' '#include "esp_eth.h"'; do
  grep -qF "$inc" "$f" || sed -i '' "1 i\\
$inc
" "$f"
done

# 2) Inietta la creazione del netif default DOPO l'install del driver e PRIMA di esp_eth_start()
#    Se già presente, non fa nulla.
if ! grep -q "esp_netif_create_default_eth_netif" "$f"; then
  # Inserisci subito dopo la PRIMA occorrenza di esp_eth_driver_install
  awk '
    BEGIN{done=0}
    {
      print $0
      if (!done && $0 ~ /esp_eth_driver_install *\(/) {
        print "    // --- netif Ethernet default: aggancia s_eth e abilita DHCP ---"
        print "    static esp_netif_t* s_eth_netif = NULL; // se già globale, unifica!"
        print "    ESP_ERROR_CHECK(esp_netif_init());"
        print "    ESP_ERROR_CHECK(esp_event_loop_create_default());"
        print "    s_eth_netif = esp_netif_create_default_eth_netif(s_eth);"
        print "    assert(s_eth_netif);"
        print "    ESP_ERROR_CHECK(esp_netif_set_hostname(s_eth_netif, \"esp32-alarm\"));"
        done=1
      }
    }' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
fi

# 3) Evita doppioni: rimuovi eventuali vecchie creazioni manuali del netif (best-effort, commenta)
perl -0777 -pe 's/esp_netif_new *\([^;]*\);/\/\/ (disabilitato) &/g' -i '' "$f"
perl -0777 -pe 's/esp_netif_attach *\([^;]*\);/\/\/ (disabilitato) &/g' -i '' "$f"
perl -0777 -pe 's/esp_netif_dhcpc_start *\([^;]*\);/\/\/ (disabilitato) &/g' -i '' "$f"

echo "[fix] ethernet.c patchato -> backup: $f.bak.$ts"
echo "[fix] build in corso…"
idf.py build
