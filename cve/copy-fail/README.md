### Exploit

1. Ubuntu 20.04.6
2. Ubuntu 24.04.4 + Kernel 6.8.0
    - sudo modprobe authenc
    - sudo modprobe authencesn
    - sudo modprobe cbc
    - sudo modprobe algif_aead
    - sudo vim /etc/modprobe.d/disable-algif_aead.conf

copy fail: CVE-2026-31431

[exploit repo](https://github.com/theori-io/copy-fail-CVE-2026-31431/blob/main/copy_fail_exp.py)
