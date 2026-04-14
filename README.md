# engsel — CLI Client (C port)

# dependensi yang dibutuhkan
'''libcurl libopenssl ca-bundle'''

```Port dari `me-cli-sunset` Python ke C, dikompilasi untuk OpenWrt.```

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
