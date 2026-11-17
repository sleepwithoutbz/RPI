import os
import subprocess
import sys
from pathlib import Path


# Fixed to the tests currently installed on this system.
# pts/timed-audio-encode exists under installed-tests, but PTS does not list it
# as a normal installed runnable test; it is omitted here.
TESTS = [
    "pts/apache",
    "pts/build-linux-kernel",
    "pts/compress-gzip",
    "pts/compress-xz",
    "pts/encode-mp3",
    "pts/git",
    "pts/nginx",
    "pts/openssl",
    "pts/osbench",
    "pts/perf-bench",
    "pts/perl-benchmark",
    "pts/redis",
    "pts/sqlite-speedtest",
    "system/gimp",
]

RESULT_IDENTIFIER = "xxxxxx"
RESULT_DESCRIPTION = "xxxxxxx"

# These choices mirror the old interactive script, translated to current
# PRESET_OPTIONS names instead of prompt menu numbers.
PRESET_OPTIONS = ";".join(
    [
        "pts/apache.concurrent=20,100",
        "pts/build-linux-kernel.build=defconfig",
        "pts/nginx.concurrent=20,100",
        "pts/openssl.algo=RSA4096,SHA256",
        "pts/osbench.test=Create Files,Create Processes,Create Threads,Launch Programs,Memory Allocations",
        "pts/perf-bench.benchmark=Sched Pipe,Memcpy 1MB,Memset 1MB,Syscall Basic,Futex Hash,Futex Lock-Pi,Epoll Wait",
        "pts/perl-benchmark.run-test=Pod2html,Interpreter",
        "pts/redis.test=SET,GET",
        "pts/redis.connections=50",
        "system/gimp.test=unsharp-mask,resize,rotate,auto-levels",
    ]
)


def pts_env(result_name):
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    env["TEST_RESULTS_NAME"] = result_name
    env["TEST_RESULTS_IDENTIFIER"] = RESULT_IDENTIFIER
    env["TEST_RESULTS_DESCRIPTION"] = RESULT_DESCRIPTION
    env["PRESET_OPTIONS"] = PRESET_OPTIONS
    return env


def run_benchmark(result_name):
    cmd = ["phoronix-test-suite", "batch-benchmark", *TESTS]
    print("Running:", " ".join(TESTS), file=sys.stderr)
    print("PRESET_OPTIONS:", PRESET_OPTIONS, file=sys.stderr)
    subprocess.run(cmd, env=pts_env(result_name), check=True)


def main(argv):
    if len(argv) < 2:
        raise SystemExit(f"Usage: {Path(argv[0]).name} RESULT_NAME")

    run_benchmark(argv[1])
    print("finish!!!")


if __name__ == "__main__":
    main(sys.argv)
