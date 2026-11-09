#pragma once
#include <ntddk.h>
#include "Kernel.h"

// -----------------------------------------------------------------------------
// DPC 链表包装
// -----------------------------------------------------------------------------
typedef struct _MY_KDPC_LIST {
    SINGLE_LIST_ENTRY ListHead;
    PSINGLE_LIST_ENTRY LastEntry;
} MY_KDPC_LIST, *PMY_KDPC_LIST;

// 每个 CPU 核心上的 DPC 控制数据结构 (KDPC_DATA)
typedef struct _MY_KDPC_DATA {
    MY_KDPC_LIST DpcList;
    ULONG_PTR DpcLock;
    volatile LONG DpcQueueDepth;
    ULONG DpcCount;
    PKDPC volatile ActiveDpc;
} MY_KDPC_DATA, *PMY_KDPC_DATA;

// 定时器哈希表项
typedef struct _MY_KTIMER_TABLE_ENTRY {
    ULONG_PTR Lock;
    LIST_ENTRY Entry;
    ULARGE_INTEGER Time;
} MY_KTIMER_TABLE_ENTRY, *PMY_KTIMER_TABLE_ENTRY;

// 定时器表结构 (每个 CPU 拥有独立的 TimerTable)
typedef struct _MY_KTIMER_TABLE {
    PKTIMER TimerExpiry[64];
    MY_KTIMER_TABLE_ENTRY TimerEntries[2][256];
} MY_KTIMER_TABLE, *PMY_KTIMER_TABLE;

// -----------------------------------------------------------------------------
// 函数导出声明 (仅聚焦 DPC 与 定时器机制)
// -----------------------------------------------------------------------------

/**
 * @brief 初始化 DPC 扫描器
 */
VOID DpcScannerInit(_In_ PDRIVER_OBJECT DriverObject);

/**
 * @brief 模块反查兼容接口 (委托给 KernelHelper)
 */
BOOLEAN DpcScannerFindModuleByAddress(
    _In_ PVOID Address,
    _Out_ PUNICODE_STRING OutModuleName,
    _Out_ PULONG_PTR OutOffset);

/**
 * @brief 高性能遍历系统中所有 CPU 的 DPC 队列与 Timer 表
 *        - Method 0 (非规范 DeferredContext 掩码识别与还原)
 *        - Method 1 (KPRCB.HalReserved[7] DPC 槽位)
 *        - Method 2 (KPRCB.AcpiReserved DPC 槽位)
 *        - RWX 内存及未背书例程深度检测
 */
VOID DpcScannerScanAllProcessors(VOID);

/**
 * @brief 扫描并诊断全局 DPC 机制：
 *        - Method 5 (全局 KiBalanceSetManagerPeriodicDpc 借壳 Hook 探测)
 *        - 独立定时器 DPC 例程 (CcBcbProfiler / CcBcbProfiler2 轮询)
 */
VOID DpcScannerDumpGlobalDpcStructures(VOID);
