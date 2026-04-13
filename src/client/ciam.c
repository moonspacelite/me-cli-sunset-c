#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "../include/client/ciam.h"
#include "../include/client/http_client.h"

// FIX: Gunakan gmtime() + offset manual +8 jam agar tidak bergantung TZ sistem.
// localtime() di OpenWrt default UTC → timestamp jadi salah 8 jam → OTP ditolak server.
static char* get_timestamp_header(void) {
    // Mundur 5 menit (trik rahasia), lalu tambah 8 jam ke UTC untuk WIB+1 / +0800
    time_t now = time(NULL) - 300 + (8 * 3600);
    struct tm *t = gmtime(&now); // gmtime: selalu UTC, portable di semua platform
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000+0800", t);
    return strdup(buf);
}

// FIX: Sama, gunakan gmtime() + offset manual
static char* get_ts_for_signature(void) {
    time_t now = time(NULL) + (8 * 3600); // waktu saat ini + 8 jam offset WIB
    struct tm *t = gmtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000+0800", t);
    return strdup(buf);
}

// Mesin Enkripsi Fingerprint
static char* generate_ax_fingerprint(const char* msisdn) {
    const char* key_str = getenv("AX_FP_KEY");
    if (!key_str) return strdup("dummy");

    char plain[256];
    snprintf(plain, sizeof(plain),
        "samsung|SM-N935F|en|720x1540|GMT07:00|192.168.1.1|1.0|Android 13|%s", msisdn);

    // Key tepat 32 bytes
    unsigned char key[32] = {0};
    size_t klen = strlen(key_str);
    memcpy(key, key_str, klen > 32 ? 32 : klen);
    unsigned char iv[16] = {0};

    // PKCS7 padding manual — identik dengan Python
    int plain_len = strlen(plain);
    int pad = 16 - (plain_len % 16);
    int padded_len = plain_len + pad;
    unsigned char padded[512] = {0};
    memcpy(padded, plain, plain_len);
    for (int i = plain_len; i < padded_len; i++) padded[i] = (unsigned char)pad;

    // Enkripsi AES-256-CBC, auto-padding dimatikan karena sudah pad manual
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

static char* generate_ax_api_signature(const char* ts_for_sign, const char* contact, const char* code, const char* contact_type, const char* key_str) {
    if (!key_str) return strdup("dummy");

    char preimage[1024];
    snprintf(preimage, sizeof(preimage), "%spassword%s%s%sopenid", ts_for_sign, contact_type, contact, code);

    unsigned char hmac[32]; unsigned int len = 32;
    HMAC(EVP_sha256(), key_str, strlen(key_str), (unsigned char*)preimage, strlen(preimage), hmac, &len);

    // Mesin Base64 Asli dari all_code_c.txt
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

cJSON* get_new_token(const char* base_ciam_url, const char* basic_auth, const char* ua, const char* refresh_token) {
    char url[512]; snprintf(url, sizeof(url), "%s/realms/xl-ciam/protocol/openid-connect/token", base_ciam_url);
    char payload[2048]; snprintf(payload, sizeof(payload), "grant_type=refresh_token&refresh_token=%s", refresh_token);
    char auth_hdr[512]; snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Basic %s", basic_auth);
    char ua_hdr[512]; snprintf(ua_hdr, sizeof(ua_hdr), "User-Agent: %s", ua);
    const char* headers[] = { "Content-Type: application/x-www-form-urlencoded", "Ax-Request-Device: samsung", "Ax-Request-Device-Model: SM-N935F", "Ax-Substype: PREPAID", "Ax-Fingerprint: dummy_fingerprint_for_testing", "Ax-Device-Id: dummy_device_id_for_testing", auth_hdr, ua_hdr };
    struct HttpResponse* response = http_post(url, headers, 8, payload);
    cJSON* result = NULL; if (response && response->body) result = cJSON_Parse(response->body);
    free_http_response(response); return result;
}

cJSON* request_otp(const char* base_ciam_url, const char* basic_auth, const char* ua, const char* number) {
    char url[512]; snprintf(url, sizeof(url), "%s/realms/xl-ciam/auth/otp?contact=%s&contactType=SMS&alternateContact=false", base_ciam_url, number);
    char auth_hdr[512]; snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Basic %s", basic_auth);
    char ua_hdr[512]; snprintf(ua_hdr, sizeof(ua_hdr), "User-Agent: %s", ua);
    char fp_hdr[1024]; char* fp = generate_ax_fingerprint(number); snprintf(fp_hdr, sizeof(fp_hdr), "Ax-Fingerprint: %s", fp); free(fp);
    char req_at[128]; char* ts_hdr = get_timestamp_header(); snprintf(req_at, sizeof(req_at), "Ax-Request-At: %s", ts_hdr); free(ts_hdr);
    char dev_id[128]; snprintf(dev_id, sizeof(dev_id), "Ax-Device-Id: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6");

    const char* headers[] = { auth_hdr, ua_hdr, "Ax-Request-Device: samsung", "Ax-Request-Device-Model: SM-N935F", "Ax-Substype: PREPAID", fp_hdr, dev_id, req_at };
    struct HttpResponse* response = http_get(url, headers, 8);
    cJSON* result = NULL; if (response && response->body && strlen(response->body) > 0) result = cJSON_Parse(response->body);
    free_http_response(response); return result;
}

cJSON* submit_otp(const char* base_ciam_url, const char* basic_auth, const char* ua, const char* ax_api_sig_key, const char* number, const char* otp) {
    char url[512]; snprintf(url, sizeof(url), "%s/realms/xl-ciam/protocol/openid-connect/token", base_ciam_url);
    char payload[1024]; snprintf(payload, sizeof(payload), "contactType=SMS&code=%s&grant_type=password&contact=%s&scope=openid", otp, number);
    
    // Gunakan 2 timestamp yang berbeda persis seperti aslimu
    char* ts_for_sign = get_ts_for_signature();
    char* signature = generate_ax_api_signature(ts_for_sign, number, otp, "SMS", ax_api_sig_key);
    
    char auth_hdr[512]; snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Basic %s", basic_auth);
    char ua_hdr[512]; snprintf(ua_hdr, sizeof(ua_hdr), "User-Agent: %s", ua);
    char sig_hdr[512]; snprintf(sig_hdr, sizeof(sig_hdr), "Ax-Api-Signature: %s", signature);
    char fp_hdr[1024]; char* fp = generate_ax_fingerprint(number); snprintf(fp_hdr, sizeof(fp_hdr), "Ax-Fingerprint: %s", fp); free(fp);
    char req_at[128]; char* ts_hdr = get_timestamp_header(); snprintf(req_at, sizeof(req_at), "Ax-Request-At: %s", ts_hdr); free(ts_hdr);
    
    // Trik Rahasia 3: ax-req-{timestamp}
    char req_id[128]; snprintf(req_id, sizeof(req_id), "Ax-Request-Id: ax-req-%ld", time(NULL));
    char dev_id[128]; snprintf(dev_id, sizeof(dev_id), "Ax-Device-Id: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6");

    const char* headers[] = { "Content-Type: application/x-www-form-urlencoded", auth_hdr, ua_hdr, sig_hdr, "Ax-Request-Device: samsung", "Ax-Request-Device-Model: SM-N935F", "Ax-Substype: PREPAID", fp_hdr, dev_id, req_at, req_id };
    
    struct HttpResponse* response = http_post(url, headers, 11, payload);
    cJSON* result = NULL; if (response && response->body && strlen(response->body) > 0) result = cJSON_Parse(response->body);
    free_http_response(response); free(ts_for_sign); free(signature); return result;
}
