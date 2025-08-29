#include "log_system.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

#define LOG_MAX 128
static log_item_t ring[LOG_MAX];
static int head=0, count=0;

esp_err_t log_system_init(void){ head=0; count=0; return 0; }
void log_add(const char* fmt, ...){
    va_list ap; va_start(ap,fmt);
    log_item_t* it = &ring[head%LOG_MAX];
    it->ts = utils_time();
    vsnprintf(it->msg,sizeof(it->msg),fmt,ap);
    head = (head+1)%LOG_MAX;
    if(count<LOG_MAX) count++;
    va_end(ap);
}
int log_dump(log_item_t* out, int max){
    int n = (count<max?count:max);
    for(int i=0;i<n;i++){
        int idx = (head - n + i + LOG_MAX)%LOG_MAX;
        out[i] = ring[idx];
    }
    return n;
}
