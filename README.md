# Introduction

This is HyperEnclave kernel module used to start HyperEnclave. See [HyperEnclave Introduction](https://github.com/HyperEnclave/hyperenclave/blob/master/README.md) for details on what is HyperEnaclave and how to use it.

# Module Build

Run the following command to compile the module:
```
$ make
```

# Module Usage

## Module insertion

Run the following command to load the module:
```
$ sudo insmod hyper_enclave.ko str_memmap=[start,size] feature_mask=[mask]
```

## Module removal

Run the following command to remove the module:
```
$ sudo rmmod hyper_enclave
```

## Module parameters

- **str_memmap** Pass security memory information for HyperEnclave  
Reserve one memory region as security memory by parameter `memmap` in kernel's command-line. Then pass the start and size of the memmap to this module by parameter `str_memmap` when start HyperEnclave.  
Note: this module will filter out the invalid memory region using E820 table provided by firmware.
	- Reserve security memory during boot-up in kernel’s command-line
	```
	memmap=size$start
	```

	- Pass security memory information to this module
	```
	str_memmap=start,size
	```

- **feature_mask** Enable/Disable HyperEnclave features  
Parameter `feature_mask` is a ulong type variable used to enable/didable HyperEnclave features:
	- Bit[0], HHBox(HyperEnclave Hypervisor Box) log feature，record hypervisor log when system is normal
		- 0 = HHBox log feature is disabled
		- 1 = HHBox log feature is enabled(default)
	- Bit[1], HHBox crash feature, cope hypervisor panic and record hypervisor log when hypervisor is abnormal.
	Besides, HHBox crash feature is based on log feature, so if enable crash feature, log feature is enabled
		- 0 = HHBox crash feature is disabled(default)
		- 1 = HHBox crash feature is enabled
	- Bits[3:2], EPC overcommit feature, indicates the EPC overcommit crypto algorithm
		- 00 = HmacSW-then-EncHW(default)
		- 01 = EncSW-then-HmacSW
		- 10 = EncHW
		- 11 = reserved
	- Bits[5:4], Stats feature, control which to record
		- 00 = stats is disabled(default)
		- 01 = EPC overcommit stats
		- 10 = EPC overcommit stats and related operation time stats
		- 11 = reserved
	- Bit[6], Shared memory feature(used to transfer data between app and enclave), indicates if shared memory is pinned
		- 0 = do not pin the shared memory(default)
		- 1 = pin the shared memory
	- Bit[7], EDMM(Enclave Dynamic Memory Management) feature, indicates whether to turn off EDMM
		- 0 = keep EDMM on(default)
		- 1 = turn off EDMM
	- Bit[8], TPM feature, indicates whether to turn on fake TPM(fake a TPM in a scenario without HW TPM and FTPM)
		- 0 = keep fake TPM off(default)
		- 1 = turn on fake TPM
	- Bit[9], Memory test feature, indicates whether to perform memory test before starting hypervisor
		- 0 = disable memory test(default)
		- 1 = enable memory test


# Compatibility

## Kernel Compatibility
This code has been tested with Linux kernel 4.19 and Linux kernel 5.4.

## GCC Compatibility
This code has been tested with GCC >= 6.5.
