#pragma once
#include "Kernel.h"
#include <intrin.h>
extern PDRIVER_OBJECT g_DriverObject;
extern PVOID g_KernelBase;
extern ULONG g_KernelSize;
extern ULONG_PTR g_MmPteBase;
extern ULONG_PTR g_MmPdeBase;
extern ULONG_PTR g_MmPdpteBase;
extern ULONG_PTR g_MmPml4eBase;
extern DYNAMIC_OFFSETS g_Offsets;

// Big Pool 追踪表 (PoolBigPageTable)
typedef struct _POOL_TRACKER_BIG_PAGES {
    volatile ULONG_PTR Va;
    ULONG Key;
    ULONG Pattern;
    ULONG_PTR NumberOfBytes;
} POOL_TRACKER_BIG_PAGES, *PPOOL_TRACKER_BIG_PAGES;

// 存储指向 nt!PoolBigPageTable 和 nt!PoolBigPageTableSize 全局变量本身的指针地址
// 注意：必须保存变量地址并在使用时动态解引用，因为 Windows 在大页池扩容时会重新分配新表并释放旧表缓冲区
extern PPOOL_TRACKER_BIG_PAGES *g_PoolBigPageTableVar;
extern PULONG g_PoolBigPageTableSizeVar;

// 独立页面系统 PTE 范围 (SystemPtes / Independent Pages)
extern ULONG_PTR g_SystemPteBase;
extern ULONG_PTR g_TotalSystemPtes;

VOID ResolvePteBase(VOID);
VOID ResolvePoolAndSystemPteInfo(VOID);
VOID ResolveDynamicOffsets(VOID);
