#include "gpio_inputs.h"
#include "mcp23017.h"
#include "ads1115.h"
#include "esp_log.h"
#include "esp_check.h"

static size_t s_ads_devices = 0;

static const char* TAG = "inputs";

#if ADS1115_COUNT > 0
static esp_err_t ensure_ads_index(size_t index)
{
    if (index >= s_ads_devices) {
        ESP_LOGE(TAG, "Indice ADS1115 %zu fuori range (dispositivi=%zu)", index, s_ads_devices);
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

static esp_err_t single_channel_mux(int channel, ads1115_mux_t* mux)
{
    if (!mux) {
        return ESP_ERR_INVALID_ARG;
    }
    switch (channel) {
        case 0: *mux = ADS1115_MUX_AIN0_GND; break;
        case 1: *mux = ADS1115_MUX_AIN1_GND; break;
        case 2: *mux = ADS1115_MUX_AIN2_GND; break;
        case 3: *mux = ADS1115_MUX_AIN3_GND; break;
        default:
            ESP_LOGE(TAG, "Canale ADS1115 non valido: %d", channel);
            return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}
#endif

esp_err_t inputs_init(void)
{
    esp_err_t e = mcp23017_init();
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "MCP23017 init failed: %s", esp_err_to_name(e));
        return e;
    }
    ESP_LOGI(TAG, "Inputs ready (MCP23017).");

#if ADS1115_COUNT > 0
    static const ads1115_device_config_t ads_cfgs[] = {
    #if ADS1115_COUNT > 0
        {
            .address = ADS1115_ADDR_0,
            .default_mux = ADS1115_MUX_AIN0_GND,
            .options = {
                .gain = ADS1115_PGA_FSR_4096,
                .mode = ADS1115_MODE_SINGLE_SHOT,
                .data_rate = ADS1115_DATA_RATE_128_SPS,
                .comp_mode = ADS1115_COMP_MODE_TRADITIONAL,
                .comp_polarity = ADS1115_COMP_POL_ACTIVE_LOW,
                .comp_latch = ADS1115_COMP_NON_LATCHING,
                .comp_queue = ADS1115_COMP_QUEUE_DISABLE,
            },
        },
    #endif
    #if ADS1115_COUNT > 1
        {
            .address = ADS1115_ADDR_1,
            .default_mux = ADS1115_MUX_AIN0_GND,
            .options = {
                .gain = ADS1115_PGA_FSR_4096,
                .mode = ADS1115_MODE_SINGLE_SHOT,
                .data_rate = ADS1115_DATA_RATE_128_SPS,
                .comp_mode = ADS1115_COMP_MODE_TRADITIONAL,
                .comp_polarity = ADS1115_COMP_POL_ACTIVE_LOW,
                .comp_latch = ADS1115_COMP_NON_LATCHING,
                .comp_queue = ADS1115_COMP_QUEUE_DISABLE,
            },
        },
    #endif
    #if ADS1115_COUNT > 2
        {
            .address = ADS1115_ADDR_2,
            .default_mux = ADS1115_MUX_AIN0_GND,
            .options = {
                .gain = ADS1115_PGA_FSR_4096,
                .mode = ADS1115_MODE_SINGLE_SHOT,
                .data_rate = ADS1115_DATA_RATE_128_SPS,
                .comp_mode = ADS1115_COMP_MODE_TRADITIONAL,
                .comp_polarity = ADS1115_COMP_POL_ACTIVE_LOW,
                .comp_latch = ADS1115_COMP_NON_LATCHING,
                .comp_queue = ADS1115_COMP_QUEUE_DISABLE,
            },
        },
    #endif
    };

    ESP_RETURN_ON_ERROR(ads1115_install(ads_cfgs, sizeof(ads_cfgs) / sizeof(ads_cfgs[0])), TAG, "ads1115");
    s_ads_devices = ads1115_device_count();
    ESP_LOGI(TAG, "ADS1115 ready: %zu device(s)", s_ads_devices);
#else
    s_ads_devices = 0;
#endif

    return ESP_OK;
}

esp_err_t inputs_read_all(uint16_t* gpioab)
{
    if (!gpioab) return ESP_ERR_INVALID_ARG;
    return mcp23017_read_gpioab(gpioab);
}

#if ADS1115_COUNT > 0
size_t inputs_ads1115_count(void)
{
    return s_ads_devices;
}

esp_err_t inputs_ads1115_read_channel_raw(size_t index, int channel, TickType_t timeout, int16_t* raw)
{
    ESP_RETURN_ON_ERROR(ensure_ads_index(index), TAG, "index");
    ESP_RETURN_ON_FALSE(raw != NULL, ESP_ERR_INVALID_ARG, TAG, "raw null");
    ads1115_mux_t mux = ADS1115_MUX_AIN0_GND;
    ESP_RETURN_ON_ERROR(single_channel_mux(channel, &mux), TAG, "channel");
    return ads1115_single_shot(index, mux, timeout, raw);
}

esp_err_t inputs_ads1115_read_channel_voltage(size_t index, int channel, TickType_t timeout, float* voltage)
{
    ESP_RETURN_ON_FALSE(voltage != NULL, ESP_ERR_INVALID_ARG, TAG, "voltage null");
    int16_t raw = 0;
    ESP_RETURN_ON_ERROR(inputs_ads1115_read_channel_raw(index, channel, timeout, &raw), TAG, "raw");
    ads1115_operating_config_t cfg;
    ESP_RETURN_ON_ERROR(ads1115_get_config(index, &cfg), TAG, "cfg");
    *voltage = ads1115_raw_to_voltage(raw, cfg.gain);
    return ESP_OK;
}

esp_err_t inputs_ads1115_read_all_raw(size_t index, TickType_t timeout_per_channel, int16_t out_raw[ADS1115_CHANNEL_COUNT])
{
    ESP_RETURN_ON_FALSE(out_raw != NULL, ESP_ERR_INVALID_ARG, TAG, "out_raw null");
    for (int ch = 0; ch < ADS1115_CHANNEL_COUNT; ++ch) {
        ESP_RETURN_ON_ERROR(inputs_ads1115_read_channel_raw(index, ch, timeout_per_channel, &out_raw[ch]), TAG, "read ch");
    }
    return ESP_OK;
}

esp_err_t inputs_ads1115_read_all_voltage(size_t index, TickType_t timeout_per_channel, float out_voltage[ADS1115_CHANNEL_COUNT])
{
    ESP_RETURN_ON_FALSE(out_voltage != NULL, ESP_ERR_INVALID_ARG, TAG, "out_voltage null");
    ads1115_operating_config_t cfg;
    ESP_RETURN_ON_ERROR(ads1115_get_config(index, &cfg), TAG, "cfg");
    for (int ch = 0; ch < ADS1115_CHANNEL_COUNT; ++ch) {
        int16_t raw = 0;
        ESP_RETURN_ON_ERROR(inputs_ads1115_read_channel_raw(index, ch, timeout_per_channel, &raw), TAG, "read ch");
        out_voltage[ch] = ads1115_raw_to_voltage(raw, cfg.gain);
    }
    return ESP_OK;
}
#endif
