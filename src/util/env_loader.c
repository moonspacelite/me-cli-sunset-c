#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/util/env_loader.h"

// Parser sederhana untuk file .env
void load_env(const char* filepath) {
    FILE* fp = fopen(filepath, "r");
    if (!fp) {
        printf("[-] File %s tidak ditemukan!\n", filepath);
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue; // Skip komentar & baris kosong
        char* sep = strchr(line, '=');
        if (sep) {
            *sep = '\0';
            char* key = line;
            char* val = sep + 1;
            val[strcspn(val, "\r\n")] = 0; // Hapus newline
            // Hapus tanda kutip jika ada
            if (val[0] == '"' && val[strlen(val)-1] == '"') {
                val[strlen(val)-1] = '\0';
                val++;
            }
            setenv(key, val, 1);
        }
    }
    fclose(fp);
}
