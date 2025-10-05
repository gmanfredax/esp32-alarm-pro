#include "audit_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char* TAG="audit";
static nvs_handle_t s_nvs = 0;
static uint16_t s_cap = 128;   // capacity
static uint16_t s_head = 0;    // next write index
static uint16_t s_count = 0;   // number of valid entries

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
        audit_entry_t ent = {0}; size_t sz=sizeof(ent);
        if (nvs_get_blob(s_nvs, key, &ent, &sz)==ESP_OK && sz==sizeof(ent)){
            char buf[256];
            int n = snprintf(buf,sizeof(buf),
                "{\"ts_us\":%lld,\"event\":\"%s\",\"user\":\"%s\",\"result\":%d,\"note\":\"%s\"}%s",
                (long long)ent.ts_us, ent.event, ent.username, ent.result, ent.note, (i+1<limit?",":""));
            httpd_resp_send_chunk(req, buf, n);
        }
    }
    httpd_resp_sendstr_chunk(req,"]");
    httpd_resp_sendstr_chunk(req,NULL);
    return ESP_OK;
}
