#!/bin/bash


sudo modprobe esp6 &&  sudo modprobe esp6_offload
sudo modprobe esp4 &&  sudo modprobe esp4_offload
sudo modprobe algif_aead

# for i in 1 2 3 4; do
#     python3 ./batch.py origin-08140122-r$i

#     (cd ./ebpf && sudo ./copy_fail_hook) &
#     python3 ./batch.py copy-fail-08140122-r$i
#     sudo kill $(pgrep copy_fail_hook)

#     (cd ./ebpf && sudo ./dirty_frag_hook) &
#     python3 ./batch.py dirty-frag-08140122-r$i
#     sudo kill $(pgrep dirty_frag_hook)

#     (cd ./ebpf && sudo ./dirty_decrypt_hook) &
#     python3 ./batch.py dirty-decrypt-08140122-r$i
#     sudo kill $(pgrep dirty_decrypt)

#     (cd ./ebpf && sudo ./fragnesia_hook) &
#     python3 ./batch.py fragnesia-08140122-r$i
#     sudo kill $(pgrep fragnesia_hook)

#     (cd ./ebpf && sudo ./common_hook) &
#     python3 ./batch.py common-08140122-r$i
#     sudo kill $(pgrep common_hook)
# done



python3 ./batch.py origin-08181338-r1
python3 ./batch.py origin-08181338-r2
python3 ./batch.py origin-08181338-r3

# Defense loaders use current-task UGO checks; common is not required.
(cd ./ebpf && sudo ./copy_fail_hook ) &
(cd ./ebpf && sudo ./dirty_frag_esp_hook) &
python3 ./batch.py two-08181338-r1
python3 ./batch.py two-08181338-r2
python3 ./batch.py two-08181338-r3
sudo kill $(pgrep copy_fail_hook)
sudo kill $(pgrep dirty_frag_esp)


(cd ./ebpf && sudo ./copy_fail_hook ) &
(cd ./ebpf && sudo ./dirty_frag_esp_hook) &
(cd ./ebpf && sudo ./dirty_decrypt_hook) &
python3 ./batch.py three-08181338-r1
python3 ./batch.py three-08181338-r2
python3 ./batch.py three-08181338-r3
sudo kill $(pgrep copy_fail_hook)
sudo kill $(pgrep dirty_frag_esp)
sudo kill $(pgrep dirty_decrypt)


(cd ./ebpf && sudo ./copy_fail_hook ) &
(cd ./ebpf && sudo ./dirty_frag_esp_hook) &
(cd ./ebpf && sudo ./dirty_decrypt_hook) &
(cd ./ebpf && sudo ./dirty_frag_rxrpc_hook) &
python3 ./batch.py four-08181338-r1
python3 ./batch.py four-08181338-r2
python3 ./batch.py four-08181338-r3
sudo kill $(pgrep copy_fail_hook)
sudo kill $(pgrep dirty_frag_esp)
sudo kill $(pgrep dirty_decrypt)
sudo kill $(pgrep dirty_frag_rxrp)


(cd ./ebpf && sudo ./copy_fail_hook) &
(cd ./ebpf && sudo ./dirty_frag_esp_hook) &
(cd ./ebpf && sudo ./dirty_decrypt_hook) &
(cd ./ebpf && sudo ./dirty_frag_rxrpc_hook) &
(cd ./ebpf && sudo ./fragnesia_hook) &
python3 ./batch.py five-08181338-r1
python3 ./batch.py five-08181338-r2
python3 ./batch.py five-08181338-r3
sudo kill $(pgrep copy_fail_hook)
sudo kill $(pgrep dirty_frag_esp)
sudo kill $(pgrep dirty_decrypt)
sudo kill $(pgrep dirty_frag_rxrp)
sudo kill $(pgrep fragnesia_hook)
