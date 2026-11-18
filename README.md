# RPI

This repository accompanies **Rapid-Deployment Runtime Defense for Linux
Page-Cache Integrity**. It contains the experimental Linux kernel, the eBPF
defense implementations, public exploit examples, and macrobenchmark scripts.

## Contents

| Directory | Contents |
| --- | --- |
| `linux-6.17/` | Linux 6.17 source used for the experiments, including the required eBPF extensions. |
| `ebpfs/` | eBPF defenses for Copy Fail, Dirty Frag (ESP and RXRPC), DirtyDecrypt, and Fragnesia, with shared permission-checking code. |
| `cve/` | Public exploit examples and references to their upstream sources. |
| `macro_test/` | Macrobenchmark configuration and scripts based on the **Phoronix Test Suite (PTS)**. |

## Build the defenses

Use an isolated x86-64 experimental VM running the supplied modified kernel.
The guards use build-specific instruction offsets; CO-RE does not make these
offsets portable to other kernel or module builds.

Install GCC, Make, Clang, libbpf development headers, and
[bpftool](https://github.com/libbpf/bpftool). With `bpftool` on `PATH`, run from
the repository root:

```sh
make -C ebpfs headers
make -C ebpfs stage
```

`headers` generates `vmlinux.h` from `/sys/kernel/btf/vmlinux` (override with
`VMLINUX_BTF=/path/to/btf` or `BPFTOOL=/path/to/bpftool`). `stage` builds the
defenses and copies the loaders and BPF objects into `macro_test/ebpf/`, as
expected by `run.sh`. Generated headers and binaries are not tracked.

For example, load Copy Fail protection with:

```sh
sudo modprobe algif_aead
cd ebpfs/ebpf-copy-fail
sudo ./copy_fail_hook
```

The loader reports successful attachment and stays running to keep the hooks
active. Stop it with Ctrl-C. The current authorization policy checks the hook
task's credentials against inode U/G/O permission bits.

## Macrobenchmarks

Install PTS using its [official installation instructions](https://github.com/phoronix-test-suite/phoronix-test-suite#installation)
(including PHP and the dependencies required by the selected test profiles).
Once `phoronix-test-suite` is on `PATH`, configure batch mode and install the
workloads listed in `batch.py`:

```sh
cd macro_test
phoronix-test-suite batch-setup
phoronix-test-suite batch-install $(python3 -c 'from batch import TESTS; print(" ".join(TESTS))')
python3 batch.py my-run
```

`batch.py` selects the workloads and their options and runs PTS under the given
result name. `run.sh` orchestrates baseline and concurrent-defense runs; after
building and staging the defenses, invoke it from `macro_test/` with
`bash run.sh`. PTS stores the generated results locally. Historical experiment
results are not included in this repository.
