#include <inttypes.h>   // <-- per PRIu32
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "mbedtls/md.h"
#include "utils.h"

static int base32_val(char c){
    if(c>='A'&&c<='Z') return c-'A';
    if(c>='2'&&c<='7') return 26+(c-'2');
    if(c>='a'&&c<='z') return c-'a';
    return -1;
}

static int base32_decode(const char* in, uint8_t* out, int outlen){
    int buffer=0, bitsLeft=0, count=0;
    for(const char* p=in; *p && count<outlen; ++p){
        if(*p=='='||*p==' '||*p=='-') continue;
        int val=base32_val(*p); if(val<0) continue;
        buffer = (buffer<<5) | val; bitsLeft += 5;
        if(bitsLeft>=8){ bitsLeft-=8; out[count++] = (uint8_t)((buffer>>bitsLeft)&0xFF); }
    }
    return count;
}

static uint32_t hotp(const uint8_t* key, int keylen, uint64_t counter){
    uint8_t msg[8]; for(int i=7;i>=0;i--){ msg[i]=counter&0xFF; counter>>=8; }
    unsigned char hmac[20]; size_t olen=0;
    mbedtls_md_context_t ctx; const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_md_init(&ctx); mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, key, keylen);
    mbedtls_md_hmac_update(&ctx, msg, 8);
    mbedtls_md_hmac_finish(&ctx, hmac);
    mbedtls_md_free(&ctx);
    int offset = hmac[19]&0x0F;
    uint32_t bin = ((hmac[offset]&0x7F)<<24) | ((hmac[offset+1]&0xFF)<<16) | ((hmac[offset+2]&0xFF)<<8) | (hmac[offset+3]&0xFF);
    return bin % 1000000;
}

bool totp_check(const char* base32_secret, const char* otp6){
    if(!base32_secret || !*base32_secret) return false;
    if(!otp6 || strlen(otp6)!=6) return false;
    uint8_t key[40]; int klen = base32_decode(base32_secret, key, sizeof(key));
    if(klen<=0) return false;
    uint64_t t = utils_time()/30ULL;
    // check window [-1,0,+1]
    for(int w=-1; w<=1; ++w){
        uint32_t code = hotp(key,klen,t+w);
        char buf[7];
        snprintf(buf, sizeof(buf), "%06" PRIu32, code);  // al posto di "%06u"
        if(memcmp(buf, otp6, 6)==0) return true;
    }
    return false;
}
