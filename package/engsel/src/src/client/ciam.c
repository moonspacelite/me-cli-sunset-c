#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include "../include/client/ciam.h"
#include "../include/client/http_client.h"

#define TZ_OFFSET_SEC (7 * 3600)

static int get_random_bytes(unsigned char *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t read = fread(buf, 1, len, f);
    fclose(f);
    return (read == len) ? 0 : -1;
}

static void generate_uuid_v4(char *out) {
    unsigned char rand[16];
    if (get_random_bytes(rand, sizeof(rand)) != 0) {
        srandom(time(NULL));
        for (int i = 0; i < 16; i++) rand[i] = random() & 0xFF;
    }
    rand[6] = (rand[6] & 0x0F) | 0x40;
    rand[8] = (rand[8] & 0x3F) | 0x80;

    sprintf(out, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            rand[0], rand[1], rand[2], rand[3],
            rand[4], rand[5],
            rand[6], rand[7],
            rand[8], rand[9],
            rand[10], rand[11], rand[12], rand[13], rand[14], rand[15]);
}

static char* md5_hex(const char *input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input, strlen(input), digest);
    char *hex = malloc(MD5_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
        sprintf(&hex[i*2], "%02x", digest[i]);
    return hex;
}

static char* generate_ax_device_id(const char* msisdn) {
    const char* key_str = getenv("AX_FP_KEY");
    if (!key_str) return strdup("dummy_device_id");

    char plain[256];
    snprintf(plain, sizeof(plain),
        "samsung|SM-N935F|en|720x1540|GMT07:00|192.168.1.1|1.0|Android 13|%s", msisdn);
    return md5_hex(plain);
}

static char* get_timestamp_header(void) {
    time_t now = time(NULL) - 300 + TZ_OFFSET_SEC;
    struct tm *t = gmtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000+0700", t);
    return strdup(buf);
}

static char* get_ts_for_signature(void) {
    time_t now = time(NULL) + TZ_OFFSET_SEC;
    struct tm *t = gmtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000+0700", t);
    return strdup(buf);
}

static char* generate_ax_fingerprint(const char* msisdn) {
    const char* key_str = getenv("AX_FP_KEY");
    if (!key_str) return strdup("dummy");

    char plain[256];
    snprintf(plain, sizeof(plain),
        "samsung|SM-N935F|en|720x1540|GMT07:00|192.168.1.1|1.0|Android 13|%s", msisdn);

    unsigned char key[32] = {0};
    size_t klen = strlen(key_str);
    memcpy(key, key_str, klen > 32 ? 32 : klen);
    unsigned char iv[16] = {0};

    int plain_len = strlen(plain);
    int pad = 16 - (plain_len % 16);
    int padded_len = plain_len + pad;
    unsigned char padded[512] = {0};
    memcpy(padded, plain, plain_len);
    for (int i = plain_len; i < padded_len; i++) padded[i] = (unsigned char)pad;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char ct[512]; int len1 = 0, len2 = 0;
    EVP_EncryptUpdate(ctx, ct, &len1, padded, padded_len);
    EVP_EncryptFinal_ex(ctx, ct + len1, &len2);
    EVP_CIPHER_CTX_free(ctx);

    int total = len1 + len2;
    char* b64 = malloc(total * 2 + 10);
    EVP_EncodeBlock((unsigned char*)b64, ct, total);
    return b64;
}

static char* generate_ax_api_signature(const char* ts_for_sign, const char* contact,
                                       const char* code, const char* contact_type, const char* key_str) {
    if (!key_str) return strdup("dummy");

    char preimage[1024];
    snprintf(preimage, sizeof(preimage), "%spassword%s%s%sopenid",
             ts_for_sign, contact_type, contact, code);

    unsigned char hmac[32]; unsigned int len = 32;
    HMAC(EVP_sha256(), (unsigned char*)key_str, strlen(key_str),
         (unsigned char*)preimage, strlen(preimage), hmac, &len);

    char* b64 = malloc(64); int b64_len = 0;
    const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 32; i += 3) {
        unsigned char a = hmac[i];
        unsigned char b = (i+1 < 32) ? hmac[i+1] : 0;
        unsigned char c = (i+2 < 32) ? hmac[i+2] : 0;
        b64[b64_len++] = table[(a >> 2) & 0x3F];
        b64[b64_len++] = table[((a & 3) << 4) | ((b >> 4) & 0xF)];
        b64[b64_len++] = (i+1 < 32) ? table[((b & 0xF) << 2) | ((c >> 6) & 0x3)] : '=';
        b64[b64_len++] = (i+2 < 32) ? table[(c & 0x3F)] : '=';
    }
    b64[b64_len] = '\0';
    return b64;
}

cJSON* get_new_token(const char* base_ciam_url, const char* basic_auth, const char* ua,
                     const char* refresh_token) {
    char url[512];
    snprintf(url, sizeof(url), "%s/realms/xl-ciam/protocol/openid-connect/token", base_ciam_url);
    char payload[2048];
    snprintf(payload, sizeof(payload), "grant_type=refresh_token&refresh_token=%s", refresh_token);
    char auth_hdr[512];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Basic %s", basic_auth);
    char ua_hdr[512];
    snprintf(ua_hdr, sizeof(ua_hdr), "User-Agent: %s", ua);
    const char* headers[] = {
        "Content-Type: application/x-www-form-urlencoded",
        "Ax-Request-Device: samsung",
        "Ax-Request-Device-Model: SM-N935F",
        "Ax-Substype: PREPAID",
        "Ax-Fingerprint: dummy_fingerprint_for_testing",
        "Ax-Device-Id: dummy_device_id_for_testing",
        auth_hdr, ua_hdr
    };
    struct HttpResponse* response = http_post(url, headers, 8, payload);
    cJSON* result = NULL;
    if (response && response->body) result = cJSON_Parse(response->body);
    free_http_response(response);
    return result;
}

cJSON* request_otp(const char* base_ciam_url, const char* basic_auth, const char* ua,
                   const char* number) {
    char url[512];
    snprintf(url, sizeof(url), "%s/realms/xl-ciam/auth/otp?contact=%s&contactType=SMS&alternateContact=false",
             base_ciam_url, number);
    char auth_hdr[512];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Basic %s", basic_auth);
    char ua_hdr[512];
    snprintf(ua_hdr, sizeof(ua_hdr), "User-Agent: %s", ua);
    char* fp = generate_ax_fingerprint(number);
    char fp_hdr[1024];
    snprintf(fp_hdr, sizeof(fp_hdr), "Ax-Fingerprint: %s", fp);
    char* dev_id = generate_ax_device_id(number);
    char dev_id_hdr[256];
    snprintf(dev_id_hdr, sizeof(dev_id_hdr), "Ax-Device-Id: %s", dev_id);
    char* ts_hdr = get_timestamp_header();
    char req_at[128];
    snprintf(req_at, sizeof(req_at), "Ax-Request-At: %s", ts_hdr);
    free(ts_hdr);
    char req_id[64];
    generate_uuid_v4(req_id);
    char req_id_hdr[128];
    snprintf(req_id_hdr, sizeof(req_id_hdr), "Ax-Request-Id: %s", req_id);

    const char* headers[] = {
        auth_hdr, ua_hdr,
        "Ax-Request-Device: samsung",
        "Ax-Request-Device-Model: SM-N935F",
        "Ax-Substype: PREPAID",
        fp_hdr, dev_id_hdr, req_at, req_id_hdr
    };
    struct HttpResponse* response = http_get(url, headers, 9);
    cJSON* result = NULL;
    if (response && response->body && strlen(response->body) > 0)
        result = cJSON_Parse(response->body);
    free_http_response(response);
    free(fp);
    free(dev_id);
    return result;
}

cJSON* submit_otp(const char* base_ciam_url, const char* basic_auth, const char* ua,
                  const char* ax_api_sig_key, const char* number, const char* otp) {
    char url[512];
    snprintf(url, sizeof(url), "%s/realms/xl-ciam/protocol/openid-connect/token", base_ciam_url);
    char payload[1024];
    snprintf(payload, sizeof(payload),
             "contactType=SMS&code=%s&grant_type=password&contact=%s&scope=openid", otp, number);

    char* ts_for_sign = get_ts_for_signature();
    char* signature = generate_ax_api_signature(ts_for_sign, number, otp, "SMS", ax_api_sig_key);

    char auth_hdr[512];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Basic %s", basic_auth);
    char ua_hdr[512];
    snprintf(ua_hdr, sizeof(ua_hdr), "User-Agent: %s", ua);
    char sig_hdr[512];
    snprintf(sig_hdr, sizeof(sig_hdr), "Ax-Api-Signature: %s", signature);
    char* fp = generate_ax_fingerprint(number);
    char fp_hdr[1024];
    snprintf(fp_hdr, sizeof(fp_hdr), "Ax-Fingerprint: %s", fp);
    char* dev_id = generate_ax_device_id(number);
    char dev_id_hdr[256];
    snprintf(dev_id_hdr, sizeof(dev_id_hdr), "Ax-Device-Id: %s", dev_id);
    char* ts_hdr = get_timestamp_header();
    char req_at[128];
    snprintf(req_at, sizeof(req_at), "Ax-Request-At: %s", ts_hdr);
    free(ts_hdr);
    char req_id[64];
    generate_uuid_v4(req_id);
    char req_id_hdr[128];
    snprintf(req_id_hdr, sizeof(req_id_hdr), "Ax-Request-Id: %s", req_id);

    const char* headers[] = {
        "Content-Type: application/x-www-form-urlencoded",
        auth_hdr, ua_hdr, sig_hdr,
        "Ax-Request-Device: samsung",
        "Ax-Request-Device-Model: SM-N935F",
        "Ax-Substype: PREPAID",
        fp_hdr, dev_id_hdr, req_at, req_id_hdr
    };

    struct HttpResponse* response = http_post(url, headers, 11, payload);
    cJSON* result = NULL;
    if (response && response->body && strlen(response->body) > 0)
        result = cJSON_Parse(response->body);
    free_http_response(response);
    free(ts_for_sign);
    free(signature);
    free(fp);
    free(dev_id);
    return result;
}
