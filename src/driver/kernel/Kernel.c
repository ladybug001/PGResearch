#include "KernelState.h"
PDRIVER_OBJECT g_DriverObject = NULL;
PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;
ULONG_PTR g_MmPteBase = 0;
ULONG_PTR g_MmPdeBase = 0;
ULONG_PTR g_MmPdpteBase = 0;
ULONG_PTR g_MmPml4eBase = 0;
DYNAMIC_OFFSETS g_Offsets = { 0 };

PPOOL_TRACKER_BIG_PAGES *g_PoolBigPageTableVar = NULL;
PULONG g_PoolBigPageTableSizeVar = NULL;
ULONG_PTR g_SystemPteBase = 0;
ULONG_PTR g_TotalSystemPtes = 0;

PVOID KernelHelperGetKernelBase(_Out_opt_ PULONG OutSize)
{
    if (OutSize != NULL) {
        *OutSize = g_KernelSize;
    }
    return g_KernelBase;
}

PDYNAMIC_OFFSETS KernelHelperGetOffsets(VOID)
{
    return &g_Offsets;
}

BOOLEAN KernelHelperInit(_In_ PDRIVER_OBJECT DriverObject)
{
    g_DriverObject = DriverObject;

    if (DriverObject != NULL && DriverObject->DriverSection != NULL) {
        __try {
            PKLDR_DATA_TABLE_ENTRY firstEntry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
            PLIST_ENTRY head = &firstEntry->InLoadOrderLinks;
            PLIST_ENTRY curr = head->Flink;

            while (curr != head && curr != NULL && MmIsAddressValid(curr)) {
                PKLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                if (MmIsAddressValid(entry) && entry->BaseDllName.Buffer != NULL) {
                    if (wcsstr(entry->BaseDllName.Buffer, L"ntoskrnl.exe") != NULL ||
                        wcsstr(entry->BaseDllName.Buffer, L"ntkrnlmp.exe") != NULL) {
                        g_KernelBase = entry->DllBase;
                        g_KernelSize = entry->SizeOfImage;
                        break;
                    }
                }
                curr = curr->Flink;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    // 动态探测 PTE 基址
    ResolvePteBase();

    // 动态定位 PoolBigPageTable 与 SystemPtes (Independent Pages)
    ResolvePoolAndSystemPteInfo();

    // 动态探测与自检各结构体偏移
    ResolveDynamicOffsets();

    return TRUE;
}
