#include "audit_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdbool.h>

static const char* TAG="audit";
static nvs_handle_t s_nvs = 0;
static uint16_t s_cap = 128;   // capacity
static uint16_t s_head = 0;    // next write index
static uint16_t s_count = 0;   // number of valid entries

typedef struct {
    int64_t ts_us;
    char event[16];
    char username[32];
    int result;
    char note[64];
} audit_entry_legacy_t;

#define NS "audit"

static esp_err_t save_meta(void){
    esp_err_t e;
    e = nvs_set_u16(s_nvs,"cap",s_cap); if(e!=ESP_OK) return e;
    e = nvs_set_u16(s_nvs,"head",s_head); if(e!=ESP_OK) return e;
    e = nvs_set_u16(s_nvs,"cnt",s_count); if(e!=ESP_OK) return e;
    return nvs_commit(s_nvs);
}

static esp_err_t load_meta(void){
    esp_err_t e;
    size_t cap=0,head=0,cnt=0;
    e = nvs_get_u16(s_nvs,"cap",&s_cap); if(e!=ESP_OK) s_cap=128;
    e = nvs_get_u16(s_nvs,"head",&s_head); if(e!=ESP_OK) s_head=0;
    e = nvs_get_u16(s_nvs,"cnt",&s_count); if(e!=ESP_OK) s_count=0;
    return ESP_OK;
}

static void key_for_index(uint16_t idx, char out[16]){
    snprintf(out,16,"e%04u", idx % s_cap);
}

esp_err_t audit_init(size_t capacity){
    if (capacity<16) capacity=16;
    if (capacity>1000) capacity=1000;
    esp_err_t e = nvs_open(NS, NVS_READWRITE, &s_nvs);
    if (e!=ESP_OK) return e;
    load_meta();
    if (s_cap != capacity){
        s_cap = (uint16_t)capacity;
        s_head = 0;
        s_count = 0;
        save_meta();
    }
    return ESP_OK;
}

void audit_append(const char* event, const char* username, int result, const char* note){
    if (!s_nvs) return;
    audit_entry_t ent = {0};
    ent.ts_us = esp_timer_get_time();
    if (event) strncpy(ent.event,event,sizeof(ent.event)-1);
    if (username) strncpy(ent.username,username,sizeof(ent.username)-1);
    ent.result = result;
    if (note) strncpy(ent.note,note,sizeof(ent.note)-1);
    struct timeval now_tv;
    if (gettimeofday(&now_tv, NULL) == 0){
        ent.wall_ts_us = (int64_t)now_tv.tv_sec * 1000000LL + (int64_t)now_tv.tv_usec;
    } else {
        ent.wall_ts_us = 0;
    }
    char key[16]; key_for_index(s_head,key);
    nvs_set_blob(s_nvs, key, &ent, sizeof(ent));
    if (s_count < s_cap) s_count++;
    s_head = (s_head + 1) % s_cap;
    save_meta();
}

esp_err_t audit_stream_json(httpd_req_t* req, size_t limit){
    if (limit==0 || limit > s_count) limit = s_count;
    httpd_resp_set_type(req,"application/json");
    httpd_resp_sendstr_chunk(req,"[");
    for (size_t i=0;i<limit;i++){
        uint16_t idx = (uint16_t)((s_head + s_cap - 1 - i) % s_cap);
        char key[16]; key_for_index(idx,key);
        size_t stored_sz = 0;
        if (nvs_get_blob(s_nvs, key, NULL, &stored_sz) != ESP_OK || stored_sz == 0) {
            continue;
        }

        audit_entry_t ent = {0};
        bool have_entry = false;

        if (stored_sz == sizeof(audit_entry_t)) {
            size_t sz = stored_sz;
            if (nvs_get_blob(s_nvs, key, &ent, &sz) == ESP_OK && sz == stored_sz) {
                have_entry = true;
            }
        } else if (stored_sz == sizeof(audit_entry_legacy_t)) {
            audit_entry_legacy_t legacy = {0};
            size_t sz = stored_sz;
            if (nvs_get_blob(s_nvs, key, &legacy, &sz) == ESP_OK && sz == stored_sz) {
                ent.ts_us = legacy.ts_us;
                memcpy(ent.event, legacy.event, sizeof(legacy.event));
                memcpy(ent.username, legacy.username, sizeof(legacy.username));
                ent.result = legacy.result;
                memcpy(ent.note, legacy.note, sizeof(legacy.note));
                ent.wall_ts_us = 0;
                have_entry = true;
            }
        } else {
            size_t sz = stored_sz < sizeof(ent) ? stored_sz : sizeof(ent);
            if (nvs_get_blob(s_nvs, key, &ent, &sz) == ESP_OK) {
                if (stored_sz < sizeof(ent)) {
                    ent.wall_ts_us = 0;
                }
                have_entry = true;
            }
        }

        if (!have_entry) {
            continue;
        }

        char buf[320];
        int n = snprintf(buf,sizeof(buf),
            "{\"ts_us\":%lld,\"wall_ts_us\":%lld,\"event\":\"%s\",\"user\":\"%s\",\"result\":%d,\"note\":\"%s\"}%s",
            (long long)ent.ts_us,
            (long long)ent.wall_ts_us,
            ent.event,
            ent.username,
            ent.result,
            ent.note,
            (i+1<limit?",":""));
        httpd_resp_send_chunk(req, buf, n);
    }
    httpd_resp_sendstr_chunk(req,"]");
    httpd_resp_sendstr_chunk(req,NULL);
    return ESP_OK;
}

int audit_dump_recent(audit_entry_t* out, size_t max){
    if (!out || max == 0 || !s_nvs || s_cap == 0) {
        return 0;
    }

    size_t available = s_count;
    if (available > max) {
        available = max;
    }

    if (available == 0) {
        return 0;
    }

    size_t written = 0;
    uint32_t cap = s_cap ? (uint32_t)s_cap : 1;
    uint32_t start = ((uint32_t)s_head + cap - (uint32_t)available) % cap;

    for (size_t i = 0; i < available; ++i) {
        uint16_t idx = (uint16_t)((start + i) % cap);
        char key[16];
        key_for_index(idx, key);
        size_t stored_sz = 0;
        esp_err_t size_res = nvs_get_blob(s_nvs, key, NULL, &stored_sz);
        if (size_res != ESP_OK || stored_sz == 0) {
            continue;
        }

        if (stored_sz == sizeof(audit_entry_t)) {
            audit_entry_t ent = {0};
            size_t sz = stored_sz;
            if (nvs_get_blob(s_nvs, key, &ent, &sz) == ESP_OK && sz == stored_sz) {
                out[written++] = ent;
            }
        } else if (stored_sz == sizeof(audit_entry_legacy_t)) {
            audit_entry_legacy_t legacy = {0};
            size_t sz = stored_sz;
            if (nvs_get_blob(s_nvs, key, &legacy, &sz) == ESP_OK && sz == stored_sz) {
                audit_entry_t ent = {0};
                ent.ts_us = legacy.ts_us;
                memcpy(ent.event, legacy.event, sizeof(legacy.event));
                memcpy(ent.username, legacy.username, sizeof(legacy.username));
                ent.result = legacy.result;
                memcpy(ent.note, legacy.note, sizeof(legacy.note));
                ent.wall_ts_us = 0;
                out[written++] = ent;
            }
        } else {
            audit_entry_t ent = {0};
            size_t sz = stored_sz < sizeof(ent) ? stored_sz : sizeof(ent);
            if (nvs_get_blob(s_nvs, key, &ent, &sz) == ESP_OK) {
                if (stored_sz < sizeof(ent)) {
                    ent.wall_ts_us = 0;
                }
                out[written++] = ent;
            }
        }
    }

    return (int)written;
}