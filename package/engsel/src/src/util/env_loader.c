#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/util/env_loader.h"

void load_env(const char* filepath) {
    FILE* fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "[-] File %s tidak ditemukan!\n", filepath);
        return;
    }
    char line[512];
    int line_num = 0;
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        char* sep = strchr(line, '=');
        if (!sep) {
            fprintf(stderr, "[!] Baris %d tidak valid (tidak ada '='): %s", line_num, line);
            continue;
        }
        *sep = '\0';
        char* key = line;
        char* val = sep + 1;
        val[strcspn(val, "\r\n")] = 0;
        size_t vallen = strlen(val);
        if (vallen >= 2 && val[0] == '"' && val[vallen-1] == '"') {
            val[vallen-1] = '\0';
            val++;
        }
        while (*key == ' ') key++;
        char* end = key + strlen(key) - 1;
        while (end > key && *end == ' ') *end-- = '\0';

        if (strlen(key) > 0 && strlen(val) > 0) {
            setenv(key, val, 1);
        } else {
            fprintf(stderr, "[!] Baris %d diabaikan (key/value kosong)\n", line_num);
        }
    }
    fclose(fp);
}
