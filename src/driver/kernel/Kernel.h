#pragma once
#include <ntddk.h>
#include <ntimage.h>

#ifdef __cplusplus
extern "C" {
#endif

// -----------------------------------------------------------------------------
// 动态内核结构体偏移定义 (消除系统版本写死硬编码)
// -----------------------------------------------------------------------------
typedef struct _DYNAMIC_OFFSETS {
    ULONG PrcbTimerTable;           // KPRCB.TimerTable
    ULONG PrcbDpcData;              // KPRCB.DpcData
    BOOLEAN IsOffsetsResolved;      // 是否已成功动态探测
} DYNAMIC_OFFSETS, *PDYNAMIC_OFFSETS;

// -----------------------------------------------------------------------------
// 内核加载模块信息节点 (DriverSection 链表)
// -----------------------------------------------------------------------------
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PVOID NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

// -----------------------------------------------------------------------------
// 函数导出声明
// -----------------------------------------------------------------------------

/**
 * @brief 初始化内核辅助模块 (探测 ntoskrnl 基址、动态解析 PTE 基址与结构体偏移)
 */
BOOLEAN KernelHelperInit(_In_ PDRIVER_OBJECT DriverObject);

/**
 * @brief 获取已缓存的全局动态偏移表指针
 */
PDYNAMIC_OFFSETS KernelHelperGetOffsets(VOID);

/**
 * @brief 获取 ntoskrnl.exe 模块基址与大小
 */
PVOID KernelHelperGetKernelBase(_Out_opt_ PULONG OutSize);

/**
 * @brief 根据内核任意地址反查所属驱动模块名及 RVA 相对偏移
 */
BOOLEAN KernelHelperFindModuleByAddress(
    _In_ PVOID Address,
    _Out_ PUNICODE_STRING OutModuleName,
    _Out_ PULONG_PTR OutOffset);

/**
 * @brief 根据内核模块基址解析指定 PE 节 (如 ".text", "PAGE") 的起始地址与尺寸
 */
PVOID KernelHelperGetSectionAddress(
    _In_ PVOID ModuleBase,
    _In_ const char* SectionName,
    _Out_ PULONG OutSectionSize);

/**
 * @brief 内存特征码查找 (支持通配符 '?')
 */
PUCHAR KernelHelperFindPattern(
    _In_ PUCHAR BaseAddress,
    _In_ ULONG Size,
    _In_ const UCHAR* Pattern,
    _In_ const char* Mask);

/**
 * @brief 判断虚拟地址是否为标准 x64 规范地址 (Canonical Address)
 *        x64 要求高 16 位必须是第 47 位的符号拓展 (0xFFFF 或 0x0000)
 */
BOOLEAN KernelHelperIsCanonicalAddress(_In_ PVOID Address);

/**
 * @brief 带页粒度缓存的地址有效性检查 (扫描热路径专用)。
 *        同 4KB 页内后续查询零成本; "无效"结果不缓存 (可能瞬态)。
 */
BOOLEAN KernelHelperIsPageValidCached(_In_ PVOID Address);

/**
 * @brief 将被 PatchGuard Method 0 掩码篡改的非规范地址还原为规范内核地址
 */
PVOID KernelHelperMakeCanonicalAddress(_In_ PVOID Address);

/**
 * @brief 查询指定虚拟地址对应的硬件 PTE 物理/虚拟条目指针
 */
PULONG_PTR KernelHelperGetPte(_In_ PVOID VirtualAddress);

/**
 * @brief 严格基于硬件分页表 (PTE) 检测内存页是否具有 RWX (可读可写可执行) 权限
 */
BOOLEAN KernelHelperIsMemoryRwx(_In_ PVOID VirtualAddress);

/**
 * @brief 检测内存页是否具备可执行 (Executable) 权限 (NX 位为 0 且 Present 为 1)
 */
BOOLEAN KernelHelperIsMemoryExecutable(_In_ PVOID VirtualAddress);

/**
 * @brief 通过 MDL 安全覆写内核只读代码段 (避免篡改 CR0.WP 触发虚拟化/PG 异常)
 */
BOOLEAN KernelHelperWriteReadOnlyMemory(
    _In_ PVOID Destination,
    _In_ const VOID* Source,
    _In_ SIZE_T Length);

/**
 * @brief 极简安全 x64 指令长度解码器 (支持跨页校验, 用于序言搬迁长度计算)
 */
ULONG KernelHelperDecodeInstructionLength(_In_ const UCHAR* Code);

#ifdef __cplusplus
}
#endif
#include "Log.h"
