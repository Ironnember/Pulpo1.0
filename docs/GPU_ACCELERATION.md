# GPU audit hashing

Pulpo's GPU path accelerates independent SHA-256 recomputation for canonical
audit-record bodies. PyTorch computes hashes on the accelerator; the CPU still
checks chain linkage, delta-root linkage, and the final verification result.
GPU output must match the CPU reference before benchmark timings are accepted.
Permit, policy, authority, replay, and durable-state decisions stay on the CPU.

## Implementations

The benchmark defaults to the fused Triton implementation, which keeps each
record's SHA-256 compression rounds inside one GPU kernel. Use
`--implementation torch` to run the original eager PyTorch implementation
for a direct comparison. The `gpu` extra installs PyTorch; use an AMD/PyTorch
environment that includes its ROCm-compatible Triton package for the fused
path.

## Backend behavior

The same implementation supports CUDA and ROCm PyTorch builds. PyTorch exposes
both through `torch.cuda` and the `cuda` tensor device namespace. The module
detects ROCm from `torch.version.hip`; pass `--device rocm` to require ROCm,
`--device cuda` to require NVIDIA CUDA, or `--device auto` to use whichever
GPU runtime the installed PyTorch build provides.

## AMD Radeon RX 7900 XT

AMD lists the RX 7900 XT as a supported RDNA 3 `gfx1100` device for ROCm.
For a predictable supported route, use Linux with an OS version in AMD's
current ROCm compatibility matrix (Ubuntu 24.04.4 or 22.04.5 are listed for
the RX 7900 XT) and install the matching AMD ROCm driver/runtime. Check AMD's
[Linux compatibility matrix](https://rocm.docs.amd.com/en/docs-7.2.3/compatibility/compatibility-matrix.html)
and [RX 7900 XT system requirements](https://rocm.docs.amd.com/projects/install-on-linux/en/docs-7.2.1/reference/system-requirements.html)
before choosing the ROCm release.

AMD publishes a PyTorch container that bundles a compatible ROCm/PyTorch stack.
From the Pulpo repository root on the supported Linux host, start the currently
documented ROCm 7.2.1 / PyTorch 2.9.1 container:

```bash
sudo docker run --rm -it --network=host \
  --device=/dev/kfd --device=/dev/dri --group-add video --ipc=host \
  --shm-size 8G -v "$PWD":/workspace -w /workspace \
  rocm/pytorch:rocm7.2.1_ubuntu24.04_py3.12_pytorch_release_2.9.1
```

Inside the container, install Pulpo's optional dependency and verify device
visibility:

```bash
python -m pip install -e ".[gpu]"
python -c "import torch; print(torch.__version__, torch.version.hip, torch.cuda.is_available(), torch.cuda.get_device_name(0))"
```

The visibility check should report a non-empty HIP version, `True`, and
`Radeon RX 7900 XT`. Then run the correctness-gated benchmark:

```bash
python scripts/benchmark_gpu.py --device rocm --implementation triton --sizes 1000,10000,100000
```

This produces JSON and CSV results in the current directory. Timings are
reported only after exact CPU/GPU hash equality for each size. PyTorch's ROCm
build uses the CUDA-named Python APIs internally; that naming does not mean the
benchmark is using NVIDIA CUDA.

To compare with the original eager path, add `--implementation torch` and use new output names. The optional `gpu` extra declares PyTorch but cannot select a ROCm wheel index
or install the matching host driver. Follow the official PyTorch or AMD install
instructions for the chosen ROCm/PyTorch version before installing the extra.

## Windows Subsystem for Linux (WSL2)

AMD's ROCm 7.2.1 WSL matrix explicitly lists the RX 7900 XT and PyTorch
2.9.1. This is the recommended route for a Windows host: install AMD's
supported WSL2 graphics driver and ROCm WSL components following the
[AMD WSL guide](https://rocm.docs.amd.com/projects/radeon-ryzen/en/docs-7.2/docs/install/installrad/wsl/install-pytorch.html)
and check the [WSL compatibility matrix](https://rocm.docs.amd.com/projects/radeon-ryzen/en/latest/docs/compatibility/compatibilityrad/wsl/wsl_compatibility.html).

In the Ubuntu WSL shell, change to the Pulpo checkout (for a C: checkout,
`cd /mnt/c/Users/<your-user>/pulpo1.0`) and start the AMD documented
ROCm 7.2 container. WSL exposes the GPU as `/dev/dxg`; do not use the native
Linux `/dev/kfd` and `/dev/dri` device arguments here.

```bash
sudo docker run --rm -it \
  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --ipc=host \
  --shm-size 8G --device=/dev/dxg \
  -v /usr/lib/wsl/lib/libdxcore.so:/usr/lib/libdxcore.so \
  -v /opt/rocm/lib/libhsa-runtime64.so.1:/opt/rocm/lib/libhsa-runtime64.so.1 \
  -v "$PWD":/workspace -w /workspace \
  rocm/pytorch:rocm7.2_ubuntu24.04_py3.12_pytorch_release_2.9.1 bash
```

Inside the container:

```bash
python -m pip install -e ".[gpu]"
python -c "import torch; print(torch.__version__, torch.version.hip, torch.cuda.is_available(), torch.cuda.get_device_name(0))"
python scripts/benchmark_gpu.py --device rocm --sizes 1000,10000,100000
```

Continue only if the check reports a non-empty HIP version, `True`, and
`Radeon RX 7900 XT`. AMD's WSL container requires the host WSL ROCm setup;
running the Linux `/dev/kfd` container command from Git Bash or ordinary
Docker Desktop does not provide that GPU path.

AMD's native Windows PyTorch support matrix has a narrower GPU list and does
not list the RX 7900 XT in its current table. Use WSL2 or a supported Linux
installation for this GPU benchmark.
