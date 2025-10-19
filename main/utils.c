#include "esp_random.h"   // <-- aggiungi questo
#include "utils.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_system.h"
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "nvs_flash.h"
#include "nvs.h"

uint64_t utils_millis(void){ return esp_timer_get_time()/1000ULL; }
uint32_t utils_time(void){ return (uint32_t)(esp_timer_get_time()/1000000ULL); }
void utils_random_token(char* out, size_t len){
    static const char* a="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for(size_t i=0;i<len;i++) out[i]=a[esp_random()%62];
}

uint64_t utils_wall_time_ms(void){
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0){
        const int64_t sec = (int64_t)tv.tv_sec;
        if (sec >= 946684800LL){ // 2000-01-01
            return (uint64_t)sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
        }
    }
    time_t now = time(NULL);
    if (now >= 946684800L){
        return (uint64_t)now * 1000ULL;
    }
    return 0;
}