# engsel — CLI Client (C port)

```Port dari `me-cli-sunset` Python ke C, dikompilasi untuk OpenWrt.```

# dependensi yang dibutuhkan

```sh 
libcurl libopenssl ca-bundle
```

## Cara install di router

### aarch64_generic (opkg)
```sh
# Upload ke router dulu
scp engsel_*.ipk root@192.168.1.1:/tmp/
atau langsung upload ke menu system > software

# Install
opkg install engsel_*.ipk
```
## Cara pakai setelah install

Ketik di terminal:
```sh
engsel
```
