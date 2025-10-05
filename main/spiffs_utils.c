#include "spiffs_utils.h"
#include "esp_spiffs.h"
#include "esp_log.h"

static const char* TAG="spiffs";

esp_err_t spiffs_init(void){
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 8,
        .format_if_mount_failed = true
    };
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK){
        ESP_LOGE(TAG,"SPIFFS mount failed: %s", esp_err_to_name(ret));
        return ret;
    }
    size_t total=0, used=0;
    esp_spiffs_info(NULL,&total,&used);
    ESP_LOGI(TAG,"SPIFFS: total=%u used=%u", (unsigned)total, (unsigned)used);
    return ESP_OK;
}
