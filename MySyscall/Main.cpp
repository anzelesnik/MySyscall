#include "NT.hpp"
#include "Signature Scan.hpp"

std::uintptr_t originalSimpleCallFunction {};

NTSTATUS ntCallUserTwoParamHook(std::uintptr_t parameter1, std::uintptr_t parameter2) {
	if (parameter1 == 0x1337 /*magic number*/) {
		DbgPrintEx(0, 0, "Hook called\n");
		return STATUS_SUCCESS;
	}

	return reinterpret_cast<NTSTATUS (*)(std::uintptr_t, std::uintptr_t)>(
		originalSimpleCallFunction)(parameter1, parameter2);
}

NTSTATUS hookSimpleCall(std::uintptr_t hookFunction) {
	std::uintptr_t moduleStart {};
	std::size_t moduleSize     {};

	// Find the start address and size of win32kfull.sys
	if (Nt::findKernelModuleByName("win32kfull.sys", &moduleStart, &moduleSize))
		return STATUS_NOT_FOUND;

	// Find the exported NtUserCallTwoParam function which contains the offset
	// to the apfnSimpleCall table which we will be hooking
	std::uintptr_t ntUserCallTwoParam {};
	if (Nt::findModuleExportByName(moduleStart, "NtUserCallTwoParam", &ntUserCallTwoParam))
		return STATUS_NOT_FOUND;

	// Signature scan for the apfnSimpleCall table offset inside the function
	auto apfnSimpleCall = Scanner::scanPattern(reinterpret_cast<std::uint8_t*>(ntUserCallTwoParam),
						   0x100, "\x48\x8D\x0D\x01\x01\x01\x01\x48\x8B\xD7", "xxx????xxx");
	if (!apfnSimpleCall)
		return STATUS_NOT_FOUND;

	// Calculate the virtual address of the function table
	apfnSimpleCall += 3;
	apfnSimpleCall += *reinterpret_cast<std::int32_t*>(apfnSimpleCall) + sizeof(std::int32_t);

	// Allocate an MDL for function entry 129 so we can write to the read-only memory
	const auto mdl = IoAllocateMdl(reinterpret_cast<PVOID>(apfnSimpleCall + 129 * 8),
							       sizeof(uintptr_t), false, false, nullptr);
	if (!mdl)
		return STATUS_INSUFFICIENT_RESOURCES;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	const auto SimpleCallRemapped = reinterpret_cast<std::uintptr_t*>(
		MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached,
		nullptr, false, HighPagePriority));
	if (!SimpleCallRemapped)
		return STATUS_INVALID_ADDRESS;

	// Replace the function pointer in the table with a pointer to our custom function
	originalSimpleCallFunction = *SimpleCallRemapped;
	*SimpleCallRemapped = hookFunction;

	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(const PDRIVER_OBJECT driverObject, const PUNICODE_STRING registryPath) {
	PEPROCESS explorerProcess {};

	// Search and attach to a session based process (like explorer.exe) because win32kfull.sys is a session based driver
	if (Nt::findProcessByName("explorer.exe", &explorerProcess)) {
		return STATUS_NOT_FOUND;
	}

	KAPC_STATE apcState {};
	KeStackAttachProcess(explorerProcess, &apcState);

	const auto status = hookSimpleCall(reinterpret_cast<std::uintptr_t>(&ntCallUserTwoParamHook));

	KeUnstackDetachProcess(&apcState);

	return status;
}