#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "../include/client/engsel.h"
#include "../include/client/http_client.h"
#include "../include/service/crypto_aes.h"
#include "../include/service/crypto_helper.h"

#define TZ_OFFSET_SEC (7 * 3600)

static int get_random_bytes(unsigned char *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t read = fread(buf, 1, len, f);
    fclose(f);
    return (read == len) ? 0 : -1;
}

static void generate_uuid(char *out) {
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

static void get_java_like_timestamp(char *out) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec + TZ_OFFSET_SEC;
    struct tm *tm = gmtime(&t);
    int ms = tv.tv_usec / 1000;
    sprintf(out, "%04d-%02d-%02dT%02d:%02d:%02d.%03d+0700",
            tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec, ms);
}

static long long get_current_time_ms() { 
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)(tv.tv_sec) * 1000 + (tv.tv_usec / 1000); 
}

cJSON* send_api_request(const char* base_url, const char* api_key, const char* xdata_key,
                        const char* api_secret, const char* path, cJSON* payload_dict,
                        const char* id_token, const char* method, const char* custom_signature) {
    char* plain_body = cJSON_PrintUnformatted(payload_dict);
    long long xtime = get_current_time_ms();
    long sig_time_sec = (long)(xtime / 1000);
    char* xdata = encrypt_xdata(plain_body, xtime, xdata_key);
    char* x_sig = custom_signature ? strdup(custom_signature)
                                   : make_x_signature(api_secret, id_token, method, path, sig_time_sec);

    cJSON* final_body_json = cJSON_CreateObject();
    cJSON_AddStringToObject(final_body_json, "xdata", xdata);
    cJSON_AddNumberToObject(final_body_json, "xtime", xtime);
    char* final_body_str = cJSON_PrintUnformatted(final_body_json);

    char uuid_str[37];
    generate_uuid(uuid_str);
    char time_str[35];
    get_java_like_timestamp(time_str);
    char sig_time_str[20];
    sprintf(sig_time_str, "%ld", sig_time_sec);

    char header_auth[4096];
    snprintf(header_auth, sizeof(header_auth), "Authorization: Bearer %s", id_token);
    char header_api_key[128];
    snprintf(header_api_key, sizeof(header_api_key), "x-api-key: %s", api_key);
    char header_sig_time[64];
    snprintf(header_sig_time, sizeof(header_sig_time), "x-signature-time: %s", sig_time_str);
    char header_sig[512];
    snprintf(header_sig, sizeof(header_sig), "x-signature: %s", x_sig);
    char header_req_id[128];
    snprintf(header_req_id, sizeof(header_req_id), "x-request-id: %s", uuid_str);
    char header_req_at[128];
    snprintf(header_req_at, sizeof(header_req_at), "x-request-at: %s", time_str);

    const char* headers[] = {
        "Content-Type: application/json; charset=utf-8",
        "User-Agent: myXL / 8.9.0(1202); com.android.vending; (samsung; SM-N935F; SDK 33; Android 13)",
        "x-hv: v3",
        "x-version-app: 8.9.0",
        header_auth, header_api_key, header_sig_time, header_sig, header_req_id, header_req_at
    };
    char url[512];
    snprintf(url, sizeof(url), "%s/%s", base_url, path);
    struct HttpResponse* response = http_post(url, headers, 10, final_body_str);

    cJSON* result = NULL;
    if (response && response->body && strlen(response->body) > 0) {
        cJSON* resp_json = cJSON_Parse(response->body);
        if (resp_json) {
            cJSON* resp_xdata = cJSON_GetObjectItem(resp_json, "xdata");
            cJSON* resp_xtime = cJSON_GetObjectItem(resp_json, "xtime");
            if (resp_xdata && resp_xtime) {
                char* decrypted = decrypt_xdata(resp_xdata->valuestring,
                                                (long long)resp_xtime->valuedouble, xdata_key);
                if (decrypted) {
                    result = cJSON_Parse(decrypted);
                    free(decrypted);
                }
            } else {
                result = cJSON_Duplicate(resp_json, 1);
            }
            cJSON_Delete(resp_json);
        }
    }
    free(plain_body);
    free(xdata);
    free(x_sig);
    cJSON_Delete(final_body_json);
    free(final_body_str);
    free_http_response(response);
    return result;
}

cJSON* get_profile(const char* base, const char* api_key, const char* xdata, const char* sec,
                   const char* id_token, const char* access_token) { 
    cJSON* p = cJSON_CreateObject();
    cJSON_AddStringToObject(p, "access_token", access_token); 
    cJSON_AddStringToObject(p, "app_version", "8.9.0"); 
    cJSON_AddBoolToObject(p, "is_enterprise", 0); 
    cJSON_AddStringToObject(p, "lang", "en");
    cJSON* res = send_api_request(base, api_key, xdata, sec, "api/v8/profile", p, id_token, "POST", NULL); 
    cJSON_Delete(p);
    return res;
}

cJSON* get_balance(const char* base, const char* api_key, const char* xdata, const char* sec,
                   const char* id_token) { 
    cJSON* p = cJSON_CreateObject();
    cJSON_AddBoolToObject(p, "is_enterprise", 0); 
    cJSON_AddStringToObject(p, "lang", "en"); 
    cJSON* res = send_api_request(base, api_key, xdata, sec, "api/v8/packages/balance-and-credit",
                                  p, id_token, "POST", NULL); 
    cJSON_Delete(p);
    return res; 
}

cJSON* get_quota(const char* base, const char* api_key, const char* xdata, const char* sec,
                 const char* id_token) { 
    cJSON* p = cJSON_CreateObject();
    cJSON_AddBoolToObject(p, "is_enterprise", 0); 
    cJSON_AddStringToObject(p, "lang", "en"); 
    cJSON_AddStringToObject(p, "family_member_id", ""); 
    cJSON* res = send_api_request(base, api_key, xdata, sec, "api/v8/packages/quota-details",
                                  p, id_token, "POST", NULL);
    cJSON_Delete(p);
    return res; 
}

cJSON* get_package_detail(const char* base, const char* api_key, const char* xdata, const char* sec,
                          const char* id_token, const char* opt_code) { 
    cJSON* p = cJSON_CreateObject();
    cJSON_AddBoolToObject(p, "is_transaction_routine", 0);
    cJSON_AddStringToObject(p, "migration_type", "NONE");
    cJSON_AddStringToObject(p, "package_family_code", "");
    cJSON_AddStringToObject(p, "family_role_hub", "");
    cJSON_AddBoolToObject(p, "is_autobuy", 0);
    cJSON_AddBoolToObject(p, "is_enterprise", 0);
    cJSON_AddBoolToObject(p, "is_shareable", 0);
    cJSON_AddBoolToObject(p, "is_migration", 0);
    cJSON_AddStringToObject(p, "lang", "en");
    cJSON_AddStringToObject(p, "package_option_code", opt_code ? opt_code : "");
    cJSON_AddBoolToObject(p, "is_upsell_pdp", 0);
    cJSON_AddStringToObject(p, "package_variant_code", "");
    cJSON* res = send_api_request(base, api_key, xdata, sec, "api/v8/xl-stores/options/detail",
                                  p, id_token, "POST", NULL);
    cJSON_Delete(p);
    return res; 
}

cJSON* get_addons(const char* base, const char* api_key, const char* xdata, const char* sec,
                  const char* id_token, const char* opt_code) { 
    cJSON* p = cJSON_CreateObject();
    cJSON_AddBoolToObject(p, "is_enterprise", 0);
    cJSON_AddStringToObject(p, "lang", "en");
    cJSON_AddStringToObject(p, "package_option_code", opt_code ? opt_code : "");
    cJSON* res = send_api_request(base, api_key, xdata, sec,
                                  "api/v8/xl-stores/options/addons-pinky-box",
                                  p, id_token, "POST", NULL);
    cJSON_Delete(p);
    return res; 
}

cJSON* get_family(const char* base, const char* api_key, const char* xdata, const char* sec,
                  const char* id_token, const char* family_code, int is_enterprise,
                  const char* migration_type) { 
    cJSON* p = cJSON_CreateObject();
    cJSON_AddBoolToObject(p, "is_show_tagging_tab", 1);
    cJSON_AddBoolToObject(p, "is_dedicated_event", 1);
    cJSON_AddBoolToObject(p, "is_transaction_routine", 0);
    cJSON_AddStringToObject(p, "migration_type", migration_type ? migration_type : "NONE");
    cJSON_AddStringToObject(p, "package_family_code", family_code ? family_code : "");
    cJSON_AddBoolToObject(p, "is_autobuy", 0);
    cJSON_AddBoolToObject(p, "is_enterprise", is_enterprise > 0 ? 1 : 0);
    cJSON_AddBoolToObject(p, "is_pdlp", 1);
    cJSON_AddStringToObject(p, "referral_code", "");
    cJSON_AddBoolToObject(p, "is_migration", 0);
    cJSON_AddStringToObject(p, "lang", "en");
    cJSON* res = send_api_request(base, api_key, xdata, sec, "api/v8/xl-stores/options/list",
                                  p, id_token, "POST", NULL); 
    cJSON_Delete(p);
    return res;
}

cJSON* unsubscribe(const char* base, const char* api_key, const char* xdata_key, const char* sec,
                   const char* id_token, const char* access_token,
                   const char* quota_code, const char* prod_subs_type,
                   const char* prod_domain) { 
    cJSON* p = cJSON_CreateObject();
    cJSON_AddStringToObject(p, "access_token", access_token);
    cJSON_AddStringToObject(p, "product_subscription_type", prod_subs_type ? prod_subs_type : "");
    cJSON_AddStringToObject(p, "quota_code", quota_code ? quota_code : "");
    cJSON_AddStringToObject(p, "product_domain", prod_domain ? prod_domain : "");
    cJSON_AddBoolToObject(p, "is_enterprise", 0);
    cJSON_AddStringToObject(p, "unsubscribe_reason_code", "");
    cJSON_AddStringToObject(p, "lang", "en");
    cJSON_AddStringToObject(p, "family_member_id", "");
    cJSON* res = send_api_request(base, api_key, xdata_key, sec, "api/v8/packages/unsubscribe",
                                  p, id_token, "POST", NULL); 
    cJSON_Delete(p);
    return res;
}

cJSON* execute_balance_purchase(const char* base, const char* key, const char* xdata,
                                const char* sec, const char* enc_key, const char* id,
                                const char* acc, const char* opt_code, int price,
                                const char* name, const char* conf,
                                const char* decoy_opt_code, int decoy_price,
                                const char* decoy_name, const char* decoy_conf,
                                const char* pay_for, int overwrite_amount,
                                int token_confirmation_idx) {
    const char* pm_target;
    const char* pm_conf;
    if (token_confirmation_idx == 1 && decoy_opt_code) {
        pm_target = decoy_opt_code;
        pm_conf   = decoy_conf;
    } else {
        pm_target = opt_code;
        pm_conf   = conf;
    }

    printf("\n[*] 1/2 Mengambil token pembayaran...\n");
    cJSON* pm_p = cJSON_CreateObject();
    cJSON_AddStringToObject(pm_p, "payment_type", "PURCHASE");
    cJSON_AddBoolToObject(pm_p, "is_enterprise", 0);
    cJSON_AddStringToObject(pm_p, "payment_target", pm_target);
    cJSON_AddStringToObject(pm_p, "lang", "en");
    cJSON_AddBoolToObject(pm_p, "is_referral", 0);
    cJSON_AddStringToObject(pm_p, "token_confirmation", pm_conf);

    cJSON* pm_res = send_api_request(base, key, xdata, sec,
                                     "payments/api/v8/payment-methods-option",
                                     pm_p, id, "POST", NULL);
    cJSON_Delete(pm_p);

    if (!pm_res || !cJSON_GetObjectItem(pm_res, "status") ||
        strcmp(cJSON_GetObjectItem(pm_res, "status")->valuestring, "SUCCESS") != 0)
        return pm_res;

    cJSON* pm_data = cJSON_GetObjectItem(pm_res, "data");
    cJSON* t_pay_node = cJSON_GetObjectItem(pm_data, "token_payment");
    cJSON* ts_node = cJSON_GetObjectItem(pm_data, "timestamp");
    if (!t_pay_node || !cJSON_IsString(t_pay_node) || !ts_node) {
        printf("[-] Fatal Error: Key token_payment/timestamp tidak ditemukan dari server.\n");
        return pm_res;
    }
    const char* t_pay = t_pay_node->valuestring;
    long ts_sign = (long)ts_node->valuedouble;

    printf("[*] 2/2 Mengeksekusi transaksi...\n");
    char payment_targets[1024];
    if (decoy_opt_code)
        snprintf(payment_targets, sizeof(payment_targets), "%s;%s", opt_code, decoy_opt_code);
    else
        snprintf(payment_targets, sizeof(payment_targets), "%s", opt_code);

    char* enc_tok = build_encrypted_field(enc_key);
    char* enc_auth = build_encrypted_field(enc_key);
    char* c_sig = make_x_signature_payment(sec, acc, ts_sign, payment_targets, t_pay,
                                           "BALANCE", pay_for,
                                           "payments/api/v8/settlement-multipayment");

    cJSON* set_p = cJSON_CreateObject();
    cJSON_AddNumberToObject(set_p, "total_discount", 0);
    cJSON_AddBoolToObject(set_p, "is_enterprise", 0);
    cJSON_AddStringToObject(set_p, "payment_token", "");
    cJSON_AddStringToObject(set_p, "token_payment", t_pay);
    cJSON_AddStringToObject(set_p, "payment_method", "BALANCE");
    cJSON_AddNumberToObject(set_p, "timestamp", ts_sign);
    cJSON_AddStringToObject(set_p, "lang", "en");
    cJSON_AddStringToObject(set_p, "payment_for", pay_for);
    cJSON_AddStringToObject(set_p, "encrypted_payment_token", enc_tok);
    cJSON_AddStringToObject(set_p, "access_token", acc);
    cJSON_AddStringToObject(set_p, "encrypted_authentication_id", enc_auth);
    cJSON_AddNumberToObject(set_p, "total_amount", overwrite_amount);

    cJSON* add_data = cJSON_AddObjectToObject(set_p, "additional_data");
    cJSON_AddNumberToObject(add_data, "original_price", price);
    cJSON_AddNumberToObject(add_data, "tax", 0);

    cJSON* items_arr = cJSON_AddArrayToObject(set_p, "items");
    cJSON* item1 = cJSON_CreateObject();
    cJSON_AddStringToObject(item1, "item_code", opt_code);
    cJSON_AddNumberToObject(item1, "item_price", price);
    cJSON_AddStringToObject(item1, "token_confirmation", conf);
    cJSON_AddItemToArray(items_arr, item1);

    if (decoy_opt_code) {
        cJSON* item2 = cJSON_CreateObject();
        cJSON_AddStringToObject(item2, "item_code", decoy_opt_code);
        cJSON_AddNumberToObject(item2, "item_price", decoy_price);
        cJSON_AddStringToObject(item2, "token_confirmation", decoy_conf);
        cJSON_AddItemToArray(items_arr, item2);
    }

    cJSON* res = send_api_request(base, key, xdata, sec,
                                  "payments/api/v8/settlement-multipayment",
                                  set_p, id, "POST", c_sig);
    free(enc_tok);
    free(enc_auth);
    free(c_sig);
    cJSON_Delete(set_p);
    cJSON_Delete(pm_res);
    return res;
}
