#include "storage.h"
#include "nvs_flash.h"
#include "nvs.h"

esp_err_t storage_init(void){
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND){
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    return err;
}

esp_err_t storage_get_blob(const char* ns, const char* key, void* out, size_t* len){
    nvs_handle_t h; esp_err_t e=nvs_open(ns,NVS_READONLY,&h); if(e!=ESP_OK) return e;
    e = nvs_get_blob(h,key,out,len);
    nvs_close(h); return e;
}
esp_err_t storage_set_blob(const char* ns, const char* key, const void* data, size_t len){
    nvs_handle_t h; esp_err_t e=nvs_open(ns,NVS_READWRITE,&h); if(e!=ESP_OK) return e;
    e = nvs_set_blob(h,key,data,len);
    if(e==ESP_OK) e = nvs_commit(h);
    nvs_close(h); return e;
}
