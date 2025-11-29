#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"

#include "expansion_node.h"

static const char *TAG = "app";

static void nvs_init_or_erase(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    } else {
        ESP_ERROR_CHECK(err);
    }
}

void app_main(void)
{
    esp_log_level_set("*", ESP_LOG_INFO);
    ESP_LOGI(TAG, "Boot ESP32 expansion node");

    nvs_init_or_erase();

    ESP_ERROR_CHECK(expansion_node_init());
    ESP_ERROR_CHECK(expansion_node_start_tasks());

    // app_main può finire qui, i task FreeRTOS fanno tutto
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
