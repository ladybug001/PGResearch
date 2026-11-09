#pragma once
#include "DpcScanner.h"
#include <intrin.h>
extern PVOID g_CcBcbProfiler;
extern PVOID g_CcBcbProfiler2;
extern ULONG_PTR g_KiWaitAlways;
extern ULONG_PTR g_KiWaitNever;
extern BOOLEAN g_WaitCookiesResolved;
extern PKDPC g_KiBalanceSetManagerPeriodicDpc;
extern PVOID g_KiBalanceSetManagerDeferredRoutine;
#define KPRCB_HAL_RESERVED_OFFSET  0x48  // HalReserved: unsigned __int64[8], PG 使用 [7] 槽位
#define KPRCB_ACPI_RESERVED_OFFSET 0xE0  // AcpiReserved: PVOID
ULONG_PTR ResolveKiWaitNever(VOID);
PVOID ResolveCcBcbProfiler(VOID);
PVOID ResolveCcBcbProfiler2(VOID);
VOID ResolveKiWaitCookies(VOID);
PKDPC DecodeTimerDpc(
    _In_ PKTIMER Timer,
    _Out_opt_ PBOOLEAN OutFullModelUsed);

// -----------------------------------------------------------------------------
// 按 CPU 编号取 PRCB (免亲和切换): ntoskrnl 导出 KeQueryPrcbAddress,
// DpcScanner (检测) 与 DpcBypass (绕过) 共享同一解析结果
// -----------------------------------------------------------------------------
typedef PVOID (*PG_KE_QUERY_PRCB_ADDRESS)(_In_ ULONG ProcessorNumber);
extern PG_KE_QUERY_PRCB_ADDRESS g_KeQueryPrcbAddress;
VOID ResolvePrcbAddressRoutine(VOID);
