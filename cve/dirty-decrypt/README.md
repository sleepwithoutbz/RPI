### Exploit

Ubuntu(24.04) + Kernel(v6.16.1)(with `CONFIG_RXGK` on)

``` shell
$ sudo sysctl -w kernel.keys.maxkeys=40000
$ sudo sysctl -w kernel.keys.maxbytes=20971520
```

CVE-2026-31635 DirtyDecrypt

[exploit repo](https://github.com/v12-security/pocs/blob/main/dirtydecrypt/poc.c)
