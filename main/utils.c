#include "esp_random.h"   // <-- aggiungi questo
#include "utils.h"
#include "esp_timer.h"
#include "esp_system.h"
#include <stdlib.h>

uint64_t utils_millis(void){ return esp_timer_get_time()/1000ULL; }
uint32_t utils_time(void){ return (uint32_t)(esp_timer_get_time()/1000000ULL); }
void utils_random_token(char* out, size_t len){
    static const char* a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for(size_t i=0;i<len;i++) out[i]=a[esp_random()%62];
}
