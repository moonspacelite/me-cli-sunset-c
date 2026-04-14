# engsel — XL Axiata CLI Client (C port)

Port dari `me-cli-sunset` Python ke C, dikompilasi untuk OpenWrt.

## Cara pakai setelah install

Ketik di terminal:
```sh
engsel
```

## Build otomatis via GitHub Actions

Setiap push ke `main`, GitHub Actions otomatis menghasilkan:

| File | Target | OpenWrt |
|------|--------|---------|
| `engsel_1.0.0-1_aarch64_generic.ipk` | aarch64_generic | 24.10 |
| `engsel-1.0.0-r1-arm_cortex-a7_neon-vfpv4.apk` | arm_cortex-a7_neon-vfpv4 | 25.05 |

Download dari tab **Actions → pilih run terbaru → Artifacts**.

Untuk release resmi: buat tag `v1.0.0` → otomatis muncul di GitHub Releases.

## Cara install di router

### OpenWrt 24.x — aarch64_generic (opkg)
```sh
# Upload ke router dulu
scp engsel_*.ipk root@192.168.1.1:/tmp/

# Install
opkg install --force-checksum /tmp/engsel_*.ipk
```

### OpenWrt 25.x — arm_cortex-a7_neon-vfpv4 (apk)
```sh
# Upload ke router dulu
scp engsel-*.apk root@192.168.1.1:/tmp/

# Install
apk add --allow-untrusted /tmp/engsel-*.apk
```

## Konfigurasi

File konfigurasi tersimpan di `/etc/engsel/`:

```
/etc/engsel/
├── .env                    ← API keys & URL (jangan diubah sembarangan)
├── refresh-tokens.json     ← Token login per nomor (auto-update)
├── bookmark.json           ← Bookmark paket favorit
├── hot_data/
│   └── hot.json            ← Data paket hot
└── decoy_data/
    └── *.json              ← Data decoy untuk pembelian
```

> **Catatan:** File `.env`, `refresh-tokens.json`, dan `bookmark.json` dipreservasi saat upgrade — data login tidak hilang.

## Struktur Repo

```
me-cli-sunset-c/
├── .github/workflows/build.yml   ← GitHub Actions (IPK + APK)
├── package/
│   └── engsel/
│       ├── Makefile              ← OpenWrt Package Makefile
│       ├── src/                  ← Source C + internal Makefile
│       │   ├── Makefile
│       │   ├── src/              ← file .c
│       │   └── include/          ← file .h
│       └── files/                ← config default
│           └── etc/engsel/
├── src/                          ← source asli (referensi)
└── include/                      ← headers asli (referensi)
```
