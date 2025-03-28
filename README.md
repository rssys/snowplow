This repository contains the artifact for the ASPLOS'25 paper:

*Sishuai Gong, Rui Wang, Deniz Altınbüken, Pedro Fonseca, Petros Maniatis, "Snowplow: Effective Kernel Fuzzing with a Learned White-box Test Mutator".*

The following instructions have been tested on an Ubuntu 20.04 virtual machine.


## Getting started
### Compile the fuzzer
The `syzkaller/` directory contains Snowplow's fuzzer implementation, which is based on Syzkaller.
To compile the fuzzer, follow these steps:
```bash
$ cd syzkaller/
$ go version
# go version go1.21.3 linux/amd64
$ make
```
Once compiled, the fuzzer binaries will be available in `syzkaller/bin/`.


### Compile the target kernel
Follow the [instructions](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md#kernel) in the official Syzkaller repo to compile the target kernel.

For convenience, we provide an example [configuration](prerequisite/kernel/.config) as a reference.
Once the kernel is compiled, set the environment variable `BZIMAGE_PATH` to the path of the kernel bzImage.

#### Perform static analysis on the compiled kernel
1. Follow the instructions under `./scripts/kernel-analysis/` to perform static analysis on the compiled kernel binary.
2. Copy the output files and the file `./prerequisite/kernel/asm-token-dict` to a designated folder.
3. Set the environment variable `KERNEL_ANALYSIS_PATH` to point to that folder.

### Prepare the VM image
Follow the [instructions](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md#image) to prepare a VM image.
Then, configure the following environment variables:
- VM_IMAGE_PATH: Path to the VM image
- VM_KEY_PATH: Path to the VM SSH key


### Set up the inference environment
Please refer to the conda [configuration](./prerequisite/inference/inference-env.yaml) file to set up the inference environment.


## Start the model inference service
On the inference machine, follow these steps to start the inference service:
```bash
cd ./prerequisite/inference
torchserve --stop
torchserve --start --ncs --model-store ./checkpoint/ --models PMModel.mar --enable-model-api --disable-token-auth --ts-config config.properties
```
Set the environment variable `INFERENCE_SERVER_IP` to the internal IP of the inference machine.

## Run the fuzzer
On the fuzzer machine, follow these steps to start testing the kernel.

### Create the fuzzer configuration file
The fuzzer requires a JSON configuration file, which should follow the structure below:
```json
{
    "target": "linux/amd64",
    "http": "127.0.0.1:1234",
    "workdir": "./workdir",
    "init_seed": 1,
    "kernel_obj": "",
    "kernel_analysis": "$KERNEL_ANALYSIS_PATH",
    "use_ml": true,
    "mlserver_addr": "$INFERENCE_SERVER_IP:7070",
    "mlsmash_exec_cnt": 2,
    "reproduce": false,
    "image": "$VM_IMAGE_PATH",
    "sshkey": "$VM_KEY_PATH",
    "syzkaller": "./syzkaller/",
    "procs": 4,
    "type": "qemu",
    "vm": {
        "count": 42,
        "kernel": "$BZIMAGE_PATH",
        "cpu": 2,
        "mem": 2048
    }
}
```

### Start the fuzzer
Execute the following command to start the fuzzer:
```bash
./syzkaller/bin/syz-manager -config=fuzz.cfg
```
