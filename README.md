# coresight-trace

coresight-trace is a hardware-assisted process tracer for binary-only fuzzing on ARM64 Linux.

CoreSight, implemented as hardware on some Arm-based SoCs for debugging purposes, enables tracing CPU execution with low-overhead. This project employs the feature to generate code coverage for fuzzing without compile-time instrumentation.

NOTE: coresight-trace is in the early development stage. Not applicable for production use.

## Prerequisites

### Hardware

Unlike Intel PT, not every Arm-based SoC has CoreSight as its design varies. The "Limitations" section describes the detailed hardware requirements and limitations.
coresight-trace supports the following boards (SoCs):

* NVIDIA Jetson TX2 (NVIDIA Parker)
* NVIDIA Jetson Nano (NVIDIA Tegra X1)
* GIGABYTE R181-T90 (Marvell ThunderX2 CN99XX)

To port coresight-trace to other boards, consult the SoC the documents whether CoreSight is available on the target.

### Environment

We tested coresight-trace on ARM64 Ubuntu 20.04 and 18.04.

coresight-trace requires bare-metal ARM64 Linux to work because it needs to access physical memories to operate CoreSight components directly. It is built on the top of customized [CSAL](https://github.com/ARM-software/CSAL), which means it does not work on VMs or containers.

coresight-trace also requires the `u-dma-buf` kernel module to use the ETR trace sink. It allocates a DMA-capable continuous physical memory region, and the tracer uses the region to store trace data.

## Getting started

To use coresight-trace for fuzzing, clone the [AFL++ CoreSight mode](https://github.com/RICSecLab/AFLplusplus-cs/tree/retrage/cs-mode-support) and check out this repository as a submodule to preserve the directory structure.

### Software Dependencies

* [RICSec/CSAL](https://github.com/RICSecLab/CSAL)
* [RICSec/coresight-decoder](https://github.com/RICSecLab/coresight-decoder)
* [ikwzm/u-dma-buf](https://github.com/ikwzm/udmabuf)

Note that coresight-decoder requires capstone disassembly library with version 4.0 or later. **Do not use the older version (e.g. `libcapstone-dev` from Ubuntu apt packages).**

### Build

coresight-trace has two build targets: `cs-trace` and `cs-proxy`.
`cs-trace` is a standalone process tracing application, which runs the traced target using fork+exec and outputs raw trace data. `cs-proxy` is a proxy application for AFL++ CoreSight mode, behaving like an AFL fork server. To use `cs-proxy` for fuzzing, read the [AFL++ CoreSight mode README](https://github.com/RICSecLab/AFLplusplus-cs/blob/retrage/cs-mode-support/cs_mode/README.md) in addition to this document.

Checkout and build:

```bash
git clone https://github.com/RICSecLab/coresight-trace.git
cd coresight-trace
git submodule update --init
DEFAULT_BOARD="Your Target Board" make
```

It will biuld `cs-proxy` only if the repository is located under the AFL++ CoreSight mode directory (In case of symbolic link `include/afl` destination `../../../include` exists).

### Install u-dma-buf

Before run cs-trace or cs-proxy, build and install the `u-dma-buf` kernel module. The allocated DMA region size is 512 KiB (0x80000) for instance:

```bash
cd u-dma-buf
make
sudo insmod u-dma-buf.ko udmabuf0=0x80000
```

It creates a `/dev/udmabuf0` pseudo-device.

### Run cs-trace

Run `cs-trace` as root with specifying a traced target after `--`.

```bash
sudo ./cs-trace -- path/to/bin
```

After the target exited, it generates the raw CoreSight trace binary `cstrace.bin`, and the coresight-decoder arguments list text file `decoderargs.txt` under the current directory.

To generate the coverage bitmap `edge_coverage_bitmap.out` using coresight-decoder from the trace binary, run:

```bash
./coresight-decoder/processor `cat decoderargs.txt`
```

Here is a pseudo Makefile target that does the above commands:

```bash
make decode
```

This runs `$(TRACEE)` (`tests/fib` by default) as a trace target under `trace/$(shell date +%Y-%m-%d-%H-%M-%S)` directory, then runs decoder.

`cs-trace` accepts some options. `-h` or `--help` for available options list.

### Coverage Types

coresight-trace uses [RICSec/coresight-decoder](https://github.com/RICSecLab/coresight-decoder), a new CoreSight trace decoder optimized for fuzzing feedback. It currently supports AFL-style edge coverage and [PTrix](https://github.com/junxzm1990/afl-pt)-style path coverage. Refer to the [coresight-decoder README](https://github.com/RICSecLab/coresight-decoder/blob/master/README.md) for further infomation.

## Limitations

Currently, coresight-trace supports trace sources with ARM64 ETMv4 and later. 32-bit Arm or ETMv3 or earlier is not supported. It also requires an ETR trace sink to achieve better performance.

## Contributing

Please open GitHub Issues and Pull Requests. All commits must include a `Signed-off-by` line using `git commit --signoff` to enforce the [Developer Certificate of Origin (DCO)](https://developercertificate.org).

## License

coresight-trace is released under the [Apache License, Version 2.0](https://opensource.org/licenses/Apache-2.0).

## Acknowledgements

This project has received funding from the Acquisition, Technology & Logistics Agency (ATLA) under the National Security Technology Research Promotion Fund 2021 (JPJ004596).
