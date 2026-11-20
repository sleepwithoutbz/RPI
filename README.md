# RPI

This repository accompanies **Rapid-Deployment Runtime Defense for Linux
Page-Cache Integrity**. It contains the modified Linux kernel source files,
the eBPF defense implementations, the SUTURE static analysis code, public
exploit examples, and macrobenchmark scripts.

## Contents

| Directory | Contents |
| --- | --- |
| `linux-6.17/` | Three modified source files for the experimental kernel's eBPF extensions, organized by their paths in upstream Linux v6.17. |
| `ebpfs/` | eBPF defenses for Copy Fail, Dirty Frag (ESP and RXRPC), DirtyDecrypt, and Fragnesia, with shared permission-checking code. |
| `SUTURE/` | LLVM-based static analysis used to track page references and identify candidate page-write sites. |
| `cve/` | Public exploit examples and references to their upstream sources. |
| `macro_test/` | Macrobenchmark configuration and scripts based on the **Phoronix Test Suite (PTS)**. |

## Prepare the experimental kernel

The experimental kernel is based on the official Linux `v6.17` tag. Copy the
three files in `linux-6.17/` into a fresh upstream checkout, preserving their
relative paths. Run these commands from the artifact repository root, then
build the modified kernel for the experimental VM.

```sh
git clone --depth 1 --branch v6.17 \
  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git \
  ../linux-v6.17-rpi
cp -R linux-6.17/. ../linux-v6.17-rpi/
```

## Build the defenses

Use an isolated x86-64 experimental VM running the modified kernel with kernel
and module BTF enabled. The guards use instruction offsets specific to the
evaluated kernel and module builds. Verify the offsets against your build
before loading the guards.

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

## Static analysis

The included SUTURE extension analyzes LLVM bitcode to trace page references
from configured entry points and report candidate page-write sites for manual
review. See the [SUTURE README](SUTURE/README.md) for setup, build, and input
format instructions.

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
