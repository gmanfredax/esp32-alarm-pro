#include "gpio_inputs.h"
#include "mcp23017.h"
#include "esp_log.h"

static const char* TAG = "inputs";

esp_err_t inputs_init(void)
{
    esp_err_t e = mcp23017_init();
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "MCP23017 init failed: %s", esp_err_to_name(e));
        return e;
    }
    ESP_LOGI(TAG, "Inputs ready (MCP23017).");
    return ESP_OK;
}

esp_err_t inputs_read_all(uint16_t* gpioab)
{
    if (!gpioab) return ESP_ERR_INVALID_ARG;
    return mcp23017_read_gpioab(gpioab);
}
