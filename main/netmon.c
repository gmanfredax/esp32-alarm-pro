#include <inttypes.h>
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_log.h"
#include "lwip/ip4_addr.h"

static const char* TAG = "netmon";

static void on_eth_event(void* arg, esp_event_base_t base, int32_t id, void* data){
    switch (id) {
        case ETHERNET_EVENT_CONNECTED:   ESP_LOGI(TAG, "ETH link UP"); break;
        case ETHERNET_EVENT_DISCONNECTED:ESP_LOGW(TAG, "ETH link DOWN"); break;
        case ETHERNET_EVENT_START:       ESP_LOGI(TAG, "ETH START"); break;
        case ETHERNET_EVENT_STOP:        ESP_LOGI(TAG, "ETH STOP"); break;
        default:                         ESP_LOGI(TAG, "ETH event: %" PRId32, id); break;
    }
}

static void on_ip_event(void* arg, esp_event_base_t base, int32_t id, void* data){
    if(id == IP_EVENT_ETH_GOT_IP){
        ip_event_got_ip_t* event = (ip_event_got_ip_t*)data;
        char ip[16], nm[16], gw[16];
        esp_ip4addr_ntoa(&event->ip_info.ip, ip, sizeof ip);
        esp_ip4addr_ntoa(&event->ip_info.netmask, nm, sizeof nm);
        esp_ip4addr_ntoa(&event->ip_info.gw, gw, sizeof gw);
        ESP_LOGI(TAG, "ETH GOT IP | ip=%s mask=%s gw=%s", ip, nm, gw);

        // DNS
        esp_netif_dns_info_t dns;
        for (int i=0;i<ESP_NETIF_DNS_MAX;i++){
            if (esp_netif_get_dns_info(event->esp_netif, i, &dns) == ESP_OK &&
                dns.addr.u_addr.ip4.addr != 0){
                char d[16];
                esp_ip4addr_ntoa(&dns.addr.u_addr.ip4, d, sizeof d);
                ESP_LOGI(TAG, "DNS[%d]=%s", i, d);
            }
        }
    }
}

void netmon_register_handlers(void){
    ESP_ERROR_CHECK(esp_event_handler_instance_register(ETH_EVENT, ESP_EVENT_ANY_ID, &on_eth_event, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &on_ip_event, NULL, NULL));
}
