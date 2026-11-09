#include "DpcState.h"
static PDRIVER_OBJECT g_DriverObject = NULL;
PVOID g_CcBcbProfiler = NULL;
PVOID g_CcBcbProfiler2 = NULL;

// 内核定时器 DPC 加密 Cookie (KeSetTimerEx 内部对 Timer->Dpc 的编码密钥)
ULONG_PTR g_KiWaitAlways = 0;
ULONG_PTR g_KiWaitNever = 0;
BOOLEAN g_WaitCookiesResolved = FALSE;

// Method 5 全局借壳对象 (KiBalanceSetManagerPeriodicDpc) 及其合法还原例程
PKDPC g_KiBalanceSetManagerPeriodicDpc = NULL;
PVOID g_KiBalanceSetManagerDeferredRoutine = NULL;



VOID DpcScannerInit(_In_ PDRIVER_OBJECT DriverObject)
{
    g_DriverObject = DriverObject;
}

BOOLEAN DpcScannerFindModuleByAddress(
    _In_ PVOID Address,
    _Out_ PUNICODE_STRING OutModuleName,
    _Out_ PULONG_PTR OutOffset)
{
    return KernelHelperFindModuleByAddress(Address, OutModuleName, OutOffset);
}

static VOID DummyDpcRoutine(
    _In_ struct _KDPC *Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
}

ULONG_PTR ResolveKiWaitNever(VOID)
{
    static ULONG_PTR s_KiWaitNever = 0;
    static BOOLEAN s_Resolved = FALSE;

    if (s_Resolved) {
        return s_KiWaitNever;
    }

    KTIMER probeTimer;
    KDPC probeDpc;
    LARGE_INTEGER dueTime;

    KeInitializeTimer(&probeTimer);
    KeInitializeDpc(&probeDpc, DummyDpcRoutine, NULL);

    // 设置一个遥远的相对超时时间 (-1000 秒，即 -10,000,000,000 个 100ns)
    // 确保绝对不会在取消前触发执行
    dueTime.QuadPart = -10000000000LL;

    KeSetTimer(&probeTimer, dueTime, &probeDpc);

    // probeTimer.Dpc 此时被内核加密: probeTimer.Dpc = (PKDPC)((ULONG_PTR)&probeDpc ^ KiWaitNever)
    ULONG_PTR encryptedDpc = (ULONG_PTR)probeTimer.Dpc;

    KeCancelTimer(&probeTimer);

    if (encryptedDpc == (ULONG_PTR)&probeDpc) {
        s_KiWaitNever = 0;
    } else {
        s_KiWaitNever = encryptedDpc ^ (ULONG_PTR)&probeDpc;
    }

    s_Resolved = TRUE;

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[Timer-Security] 动态已知明文反解 KiWaitNever: 0x%016llX (%s)\n",
        (unsigned long long)s_KiWaitNever,
        s_KiWaitNever != 0 ? "内核已启用异或加密防护" : "系统未加密"));

    return s_KiWaitNever;
}

PVOID ResolveCcBcbProfiler(VOID)
{
    if (g_CcBcbProfiler != NULL) {
        return g_CcBcbProfiler;
    }

    ULONG kernelSize = 0;
    PVOID kernelBase = KernelHelperGetKernelBase(&kernelSize);
    if (kernelBase == NULL || kernelSize == 0) {
        PgReportError(PgMethod5, "kernel base unavailable");
        PgReportError(PgIndependentTimer, "kernel base unavailable");
        return NULL;
    }

    const UCHAR bcbInitPattern[] = {
        0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,
        0xC7, 0x03, 0x13, 0x01, 0x00, 0x00,
        0x48, 0x89, 0x43, 0x18
    };
    const char bcbInitMask[] = "xxx????xxxxxxxxxx";

    PUCHAR matchBcb = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, bcbInitPattern, bcbInitMask);
    if (matchBcb != NULL) {
        LONG disp = *(PLONG)(matchBcb + 3);
        g_CcBcbProfiler = (PVOID)(matchBcb + 7 + disp);
    } else {
        const UCHAR bcbFuncPattern[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08,
            0x48, 0x89, 0x6C, 0x24, 0x18,
            0x48, 0x89, 0x74, 0x24, 0x20,
            0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
            0x48, 0x83, 0xEC, 0x60
        };
        const char bcbFuncMask[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        PUCHAR matchBcbFunc = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, bcbFuncPattern, bcbFuncMask);
        if (matchBcbFunc != NULL) {
            g_CcBcbProfiler = (PVOID)matchBcbFunc;
        }
    }

    return g_CcBcbProfiler;
}

PVOID ResolveCcBcbProfiler2(VOID)
{
    if (g_CcBcbProfiler2 != NULL) {
        return g_CcBcbProfiler2;
    }

    ULONG kernelSize = 0;
    PVOID kernelBase = KernelHelperGetKernelBase(&kernelSize);
    if (kernelBase == NULL || kernelSize == 0) {
        return NULL;
    }

    // CcBcbProfiler2 (sub_1405CC010) 函数序言 (push rbx/rbp/rsi/rdi; push r12,r14,r15; sub rsp,?; mov rsi,rcx; call)
    const UCHAR bcb2Pattern[] = {
        0x40, 0x53,
        0x55, 0x56, 0x57,
        0x41, 0x54, 0x41, 0x56, 0x41, 0x57,
        0x48, 0x83, 0xEC, 0x00,
        0x48, 0x8B, 0xF1,
        0xE8
    };
    const char bcb2Mask[] = "xxxxxxxxxxxxxxx?xxxx";

    // 优先在 PAGE 节内精确扫描, 失败后回退全镜像
    ULONG pageSectionSize = 0;
    PUCHAR pageBase = (PUCHAR)KernelHelperGetSectionAddress(kernelBase, "PAGE", &pageSectionSize);
    if (pageBase != NULL && pageSectionSize > 0) {
        g_CcBcbProfiler2 = (PVOID)KernelHelperFindPattern(pageBase, pageSectionSize, bcb2Pattern, bcb2Mask);
    }
    if (g_CcBcbProfiler2 == NULL) {
        g_CcBcbProfiler2 = (PVOID)KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, bcb2Pattern, bcb2Mask);
    }

    return g_CcBcbProfiler2;
}

VOID ResolveKiWaitCookies(VOID)
{
    if (g_WaitCookiesResolved) {
        return;
    }
    g_WaitCookiesResolved = TRUE;

    ULONG kernelSize = 0;
    PVOID kernelBase = KernelHelperGetKernelBase(&kernelSize);
    if (kernelBase == NULL || kernelSize == 0) {
        return;
    }

    ULONG textSectionSize = 0;
    PUCHAR textBase = (PUCHAR)KernelHelperGetSectionAddress(kernelBase, ".text", &textSectionSize);
    PUCHAR scanBase = (textBase != NULL && textSectionSize > 0) ? textBase : (PUCHAR)kernelBase;
    ULONG scanSize = (textBase != NULL && textSectionSize > 0) ? textSectionSize : kernelSize;

    // KiWaitNever & KiWaitAlways: KeSetTimerEx 内部高精度双 Cookie 引用签名:
    //   mov rax, cs:KiWaitNever   ; 48 8B 05 [disp32]
    //   mov rdi, rcx              ; 48 8B F9
    //   mov rsi, cs:KiWaitAlways  ; 48 8B 35 [disp32]
    //   mov r14, r9               ; 4D 8B F1
    //   xor rsi, r9               ; 49 33 F1
    const UCHAR neverPattern[] = {
        0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0xF9,
        0x48, 0x8B, 0x35, 0x00, 0x00, 0x00, 0x00,
        0x4D, 0x8B, 0xF1,
        0x49, 0x33, 0xF1
    };
    const char neverMask[] = "xxx????xxxxxx????xxxxxx";

    // 备用独立 KiWaitAlways 特征码 (KeSetTimerEx 内部)
    const UCHAR alwaysPattern[] = {
        0x48, 0x8B, 0x35, 0x00, 0x00, 0x00, 0x00,
        0x4D, 0x8B, 0xF1,
        0x49, 0x33, 0xF1
    };
    const char alwaysMask[] = "xxx????xxxxxx";

    PUCHAR matchNever = KernelHelperFindPattern(scanBase, scanSize, neverPattern, neverMask);
    if (matchNever == NULL && scanBase != (PUCHAR)kernelBase) {
        matchNever = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, neverPattern, neverMask);
    }

    PUCHAR matchAlways = KernelHelperFindPattern(scanBase, scanSize, alwaysPattern, alwaysMask);
    if (matchAlways == NULL && scanBase != (PUCHAR)kernelBase) {
        matchAlways = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, alwaysPattern, alwaysMask);
    }

    __try {
        if (matchNever != NULL) {
            // 引用 1: mov rax, cs:KiWaitNever (偏移 +3 处 disp32, 目标 = match + 7 + disp)
            LONG dispNever = *(PLONG)(matchNever + 3);
            PULONG_PTR pNever = (PULONG_PTR)(matchNever + 7 + dispNever);
            if (MmIsAddressValid(pNever)) {
                g_KiWaitNever = *pNever;
            }

            // 引用 2: 同一特征内的 mov rsi, cs:KiWaitAlways (偏移 +13 处 disp32, 目标 = match + 17 + disp)
            // 一处匹配即可同时解出双 Cookie, 这是完整 bswap+rotl 模型的唯一稳定来源
            LONG dispAlways = *(PLONG)(matchNever + 13);
            PULONG_PTR pAlways = (PULONG_PTR)(matchNever + 17 + dispAlways);
            if (MmIsAddressValid(pAlways)) {
                g_KiWaitAlways = *pAlways;
            }
        }

        // 回退: 独立 KiWaitAlways 特征码 (上一步未能提取时)
        if (g_KiWaitAlways == 0 && matchAlways != NULL) {
            LONG disp = *(PLONG)(matchAlways + 3);
            PULONG_PTR pAlways = (PULONG_PTR)(matchAlways + 7 + disp);
            if (MmIsAddressValid(pAlways)) {
                g_KiWaitAlways = *pAlways;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (g_KiWaitAlways != 0 || g_KiWaitNever != 0) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[DpcScanner] 已反解定时器加密 Cookie: KiWaitNever=%016llX, KiWaitAlways=%016llX (bswap+rotl 完整模型)\n",
            (unsigned long long)g_KiWaitNever, (unsigned long long)g_KiWaitAlways));
    } else {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[DpcScanner] 未能特征定位加密 Cookie, 解密/加密回退探针实测异或模型\n"));
    }
}

PKDPC DecodeTimerDpc(
    _In_ PKTIMER Timer,
    _Out_opt_ PBOOLEAN OutFullModelUsed)
{
    if (OutFullModelUsed != NULL) {
        *OutFullModelUsed = FALSE;
    }

    ULONG_PTR rawDpcVal = (ULONG_PTR)Timer->Dpc;
    if (rawDpcVal == 0) {
        return NULL;
    }

    PKDPC realDpc = NULL;
    BOOLEAN fullModel = FALSE;

    // 优先: 完整 Cookie 模型 (Dpc = KiWaitAlways ^ bswap64(Timer ^ rotl64(raw ^ KiWaitNever, (UCHAR)KiWaitNever)))
    if (g_KiWaitAlways != 0 || g_KiWaitNever != 0) {
        ULONG_PTR decoded = g_KiWaitAlways ^ (ULONG_PTR)_byteswap_uint64(
            (ULONG64)(ULONG_PTR)Timer ^ (ULONG64)_rotl64(
                (ULONG64)rawDpcVal ^ (ULONG64)g_KiWaitNever,
                (int)(UCHAR)g_KiWaitNever));

        if (KernelHelperIsCanonicalAddress((PVOID)decoded) && MmIsAddressValid((PVOID)decoded)) {
            realDpc = (PKDPC)decoded;
            fullModel = TRUE;
        }
    }

    // 回退 1: 探针实测的简单异或模型 (Timer->Dpc = Dpc ^ KiWaitNever)
    if (realDpc == NULL) {
        ULONG_PTR xorKey = ResolveKiWaitNever();
        if (xorKey != 0) {
            ULONG_PTR decoded = rawDpcVal ^ xorKey;
            if (KernelHelperIsCanonicalAddress((PVOID)decoded) && MmIsAddressValid((PVOID)decoded)) {
                realDpc = (PKDPC)decoded;
            }
        }
    }

    // 回退 2: 系统未启用加密, 密文即明文
    if (realDpc == NULL &&
        KernelHelperIsCanonicalAddress((PVOID)rawDpcVal) && MmIsAddressValid((PVOID)rawDpcVal)) {
        realDpc = (PKDPC)rawDpcVal;
    }

    // 自洽校验: 解出的对象其 DeferredRoutine 必须为规范可读地址, 否则视为解码失败
    if (realDpc != NULL) {
        __try {
            if (!KernelHelperIsCanonicalAddress(realDpc->DeferredRoutine) ||
                !MmIsAddressValid(realDpc->DeferredRoutine)) {
                realDpc = NULL;
                fullModel = FALSE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            realDpc = NULL;
            fullModel = FALSE;
        }
    }

    if (realDpc != NULL && fullModel && OutFullModelUsed != NULL) {
        *OutFullModelUsed = TRUE;
    }

    return realDpc;
}

static VOID InspectDpcObject(
    _In_ PKDPC Dpc,
    _In_ const char* SourceTag,
    _In_ ULONG CpuIndex,
    _In_ ULONG Period,
    _In_ ULONGLONG DueTime)
{
    if (Dpc == NULL || !KernelHelperIsPageValidCached(Dpc)) {
        PgReportPartial(PgMethod0, "DPC object unreadable");
        PgReportPartial(PgIndependentTimer, "DPC object unreadable");
        return;
    }

    __try {
        PVOID routine = Dpc->DeferredRoutine;
        PVOID context = Dpc->DeferredContext;

        UNICODE_STRING modName = { 0 };
        ULONG_PTR offset = 0;
        BOOLEAN hasModule = KernelHelperFindModuleByAddress(routine, &modName, &offset);
        BOOLEAN isRwx = KernelHelperIsMemoryRwx(routine);
        BOOLEAN isCtxCanonical = KernelHelperIsCanonicalAddress(context);

        // 判定 1: Method 0 关键特征 (DeferredContext 为非规范地址)
        BOOLEAN isMethod0 = (context != NULL && !isCtxCanonical);
        PVOID decodedContext = isMethod0 ? KernelHelperMakeCanonicalAddress(context) : context;

        // 判定 2: 代码是否驻留于未背书内存或 RWX 可写执行内存
        BOOLEAN isSuspiciousCode = (!hasModule || isRwx);

        // 判定 3: 独立定时器例程特征 (CcBcbProfiler / CcBcbProfiler2 / 2分钟周期轮询)
        BOOLEAN isCcBcbProfiler = (g_CcBcbProfiler != NULL && routine == g_CcBcbProfiler) ||
                                  (g_CcBcbProfiler2 != NULL && routine == g_CcBcbProfiler2);
        BOOLEAN isTwoMinuteTimer = (Period == 120000);

        // 计算 DueTime 相对当前中断时间的剩余倒计时 (毫秒/秒)
        ULONGLONG now = KeQueryInterruptTime();
        LONGLONG remainingNs = (DueTime != 0) ? ((LONGLONG)DueTime - (LONGLONG)now) : 0;
        LONGLONG remainingMs = remainingNs / 10000;
        LONGLONG remSec = remainingMs / 1000;
        LONGLONG remFrac = (remainingMs < 0 ? -remainingMs : remainingMs) % 1000 / 100;

        // 判定 4: PG 单次自重挂轮询特征 (Period == 0, 但 DueTime 倒计时在 ~2 分钟窗口内且代码/上下文可疑)
        BOOLEAN isSuspiciousDueTime = (Period == 0 && DueTime != 0 && remainingMs > 0 && remainingMs <= 180000);
        BOOLEAN isOneShotPgTimer = isSuspiciousDueTime && (isMethod0 || !hasModule);
        PgReportScanned(PgMethod0, 1);
        PgReportScanned(PgIndependentTimer, 1);
        PgReportFound(PgMethod0, PgSuspected, (isMethod0 || isOneShotPgTimer) ? Dpc : NULL, CpuIndex, NULL, "original context/timer heuristic");

        if (isCcBcbProfiler) {
            PgReportIndependentDpc(Dpc, CpuIndex, SourceTag);

            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  [CRIT!] [CPU %02u] [%s] %p [!] [PG-Signature] 捕获正在运行的 PatchGuard 独立定时器 (CcBcbProfiler)!\n"
                "          -> DeferredRoutine: %p (%wZ+0x%llX) [精准匹配 CcBcbProfiler 入口]\n"
                "          -> DeferredContext: %p (Canonical: %s)%s%p\n"
                "          -> Timer 周期:      %u ms%s\n",
                CpuIndex, SourceTag, Dpc,
                routine, &modName, (unsigned long long)offset,
                context, isCtxCanonical ? "YES" : "NO! [Method 0 非规范地址混淆]",
                isMethod0 ? " -> 还原物理上下文: " : "",
                isMethod0 ? decodedContext : NULL,
                Period,
                isTwoMinuteTimer ? " (精准匹配 2 分钟周期!)" : ""));

            if (DueTime != 0) {
                PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "          -> 到期时间 (Due):  0x%016llX (%s %lld.%lld 秒触发)\n",
                    (unsigned long long)DueTime,
                    remainingMs < 0 ? "已过期" : "剩余",
                    remainingMs < 0 ? -remSec : remSec, remFrac));
            }
        } else if ((isTwoMinuteTimer && (isMethod0 || !hasModule)) || isOneShotPgTimer) {
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  [CRIT!] [CPU %02u] [%s] %p [!] [PG-Signature] 捕获高危定时器 (疑似 PG %s)!\n"
                "          -> DeferredRoutine: %p (%s%wZ+0x%llX%s)%s\n"
                "          -> DeferredContext: %p (Canonical: %s)%s%p\n"
                "          -> Timer 周期:      %u ms%s\n",
                CpuIndex, SourceTag, Dpc,
                isOneShotPgTimer ? "单次自重挂轮询" : "2 分钟周期轮询",
                routine,
                hasModule ? "" : "[UNBACKED] ",
                &modName, (unsigned long long)offset,
                hasModule ? "" : " (无驱动背书)",
                isRwx ? " [RWX 内存!]" : "",
                context, isCtxCanonical ? "YES" : "NO! [Method 0 非规范地址混淆]",
                isMethod0 ? " -> 还原物理上下文: " : "",
                isMethod0 ? decodedContext : NULL,
                Period,
                isTwoMinuteTimer ? " (2 分钟轮询)" : (isOneShotPgTimer ? " (单次自重挂定时器)" : "")));

            if (DueTime != 0) {
                PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "          -> 到期时间 (Due):  0x%016llX (%s %lld.%lld 秒触发%s)\n",
                    (unsigned long long)DueTime,
                    remainingMs < 0 ? "已过期" : "剩余",
                    remainingMs < 0 ? -remSec : remSec, remFrac,
                    isOneShotPgTimer ? ", 命中 ~2 分钟自重挂倒计时窗口!" : ""));
            }
        } else if (isTwoMinuteTimer) {
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  [ WARN ] [CPU %02u] [%s] %p 捕获 2 分钟周期定时器 (疑似 PG 完整性校验例程)\n"
                "          -> Routine: %p (%wZ+0x%llX) | Period: 120,000ms\n",
                CpuIndex, SourceTag, Dpc, routine, &modName, (unsigned long long)offset));
            if (DueTime != 0) {
                PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "          -> 到期时间 (Due):  0x%016llX (%s %lld.%lld 秒)\n",
                    (unsigned long long)DueTime,
                    remainingMs < 0 ? "已过期" : "剩余",
                    remainingMs < 0 ? -remSec : remSec, remFrac));
            }
        } else if (isMethod0 || isSuspiciousCode) {
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "  [CRIT!] [CPU %02u] [%s] %p [!] 发现高危/PG 异常 DPC!\n"
                "          -> Routine: %p (%s%wZ+0x%llX%s)%s\n"
                "          -> Context: %p %s%p\n"
                "          -> Period:  %u ms\n",
                CpuIndex, SourceTag, Dpc,
                routine,
                hasModule ? "" : "[UNBACKED] ",
                &modName, (unsigned long long)offset,
                hasModule ? "" : " (无驱动背书)",
                isRwx ? " [RWX 内存!]" : "",
                context,
                isMethod0 ? "[!] PG Method 0 掩码上下文! 还原为: " : "[规范地址]",
                isMethod0 ? decodedContext : NULL,
                Period));
            if (DueTime != 0) {
                PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "          -> 到期时间 (Due):  0x%016llX (%s %lld.%lld 秒)\n",
                    (unsigned long long)DueTime,
                    remainingMs < 0 ? "已过期" : "剩余",
                    remainingMs < 0 ? -remSec : remSec, remFrac));
            }
        } else {
            // 常规合法驱动的 DPC：静默放行，不向控制台刷屏
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        PgReportPartial(PgMethod0, "DPC inspection interrupted");
        PgReportPartial(PgIndependentTimer, "DPC inspection interrupted");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "  [ WARN ] [CPU %02u] [%s] %p 读取过程发生访问违规\n", CpuIndex, SourceTag, Dpc));
    }
}

static VOID DumpProcessorPatchGuardFields(_In_ ULONG CpuIndex, _In_ PUCHAR Prcb)
{
    const ULONG HAL_RESERVED_OFFSET = KPRCB_HAL_RESERVED_OFFSET;   // HalReserved: unsigned __int64[8]
    const ULONG ACPI_RESERVED_OFFSET = KPRCB_ACPI_RESERVED_OFFSET; // AcpiReserved: PVOID

    PULONG64 halReserved = (PULONG64)(Prcb + HAL_RESERVED_OFFSET);
    PVOID acpiReserved = *(PVOID*)(Prcb + ACPI_RESERVED_OFFSET);

    BOOLEAN hasAcpi = (acpiReserved != NULL);
    BOOLEAN hasHal = (halReserved[7] != 0);


    if (!hasAcpi && !hasHal) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  [  OK  ] [CPU %02u] 专用锚点 (HalReserved[7] / AcpiReserved): 洁净 (均为 NULL)\n", CpuIndex));
        return;
    }

    PgReportScanned(PgMethod1, 1);
    PgReportScanned(PgMethod2, 1);
    PgReportFound(PgMethod1, PgSuspected, hasHal ? (PVOID)(ULONG_PTR)halReserved[7] : NULL, CpuIndex, NULL, "non-empty HalReserved[7]");
    PgReportFound(PgMethod2, PgSuspected, hasAcpi ? acpiReserved : NULL, CpuIndex, NULL, "non-empty AcpiReserved; original numbering");
    PgReportPartialIf(PgMethod2, hasAcpi && !MmIsAddressValid(acpiReserved), "reserved DPC object unreadable");
    PgReportPartialIf(PgMethod0, hasAcpi && !MmIsAddressValid(acpiReserved), "reserved DPC object unreadable");
    PgReportPartialIf(PgIndependentTimer, hasAcpi && !MmIsAddressValid(acpiReserved), "reserved DPC object unreadable");
    PgReportPartialIf(PgMethod1, halReserved[7] != 0 && !MmIsAddressValid((PVOID)halReserved[7]), "reserved DPC object unreadable");
    PgReportPartialIf(PgMethod0, halReserved[7] != 0 && !MmIsAddressValid((PVOID)halReserved[7]), "reserved DPC object unreadable");
    PgReportPartialIf(PgIndependentTimer, halReserved[7] != 0 && !MmIsAddressValid((PVOID)halReserved[7]), "reserved DPC object unreadable");
    if (hasAcpi) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  [CRIT!] [CPU %02u] KPRCB.AcpiReserved: %p [!] 命中 Method 2 锚点！\n", CpuIndex, acpiReserved));
        if (MmIsAddressValid(acpiReserved)) {
            InspectDpcObject((PKDPC)acpiReserved, "AcpiReserved-DPC(Method 2)", CpuIndex, 0, 0);
        }
    }

    if (hasHal) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  [CRIT!] [CPU %02u] KPRCB.HalReserved[7]: %016llX [!] 命中 Method 1 锚点！\n", CpuIndex, halReserved[7]));
        if (halReserved[7] != 0 && MmIsAddressValid((PVOID)halReserved[7])) {
            InspectDpcObject((PKDPC)halReserved[7], "HalReserved[7]-DPC(Method 1)", CpuIndex, 0, 0);
        }
    }
}

VOID DpcScannerDumpGlobalDpcStructures(VOID)
{
    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "\n================ [PatchGuard 全局 DPC 结构与独立定时器诊断] ================\n"));

    ULONG kernelSize = 0;
    PVOID kernelBase = KernelHelperGetKernelBase(&kernelSize);

    if (kernelBase == NULL || kernelSize == 0) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[DpcScanner] 未能获取 ntoskrnl.exe 模块基址，跳过全局特征定位\n"));
        return;
    }

    // -------------------------------------------------------------------------
    // 优先获取 .text 代码节，提升扫描速度并保障绝对内存安全
    // -------------------------------------------------------------------------
    ULONG textSectionSize = 0;
    PUCHAR textBase = (PUCHAR)KernelHelperGetSectionAddress(kernelBase, ".text", &textSectionSize);
    PUCHAR scanBase = (textBase != NULL && textSectionSize > 0) ? textBase : (PUCHAR)kernelBase;
    ULONG scanSize = (textBase != NULL && textSectionSize > 0) ? textSectionSize : kernelSize;

    // -------------------------------------------------------------------------
    // 1. 全局变量 KiBalanceSetManagerPeriodicDpc (Method 5: 周期性平衡集管理器 DPC)
    // -------------------------------------------------------------------------
    const UCHAR dpcPattern[] = {
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0x45, 0x33, 0xC9,
        0x89, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x45, 0x33, 0xC0
    };
    const char dpcMask[] = "xxx????xxxx????xxx";

    PUCHAR matchDpc = KernelHelperFindPattern(scanBase, scanSize, dpcPattern, dpcMask);
    if (matchDpc == NULL && scanBase != (PUCHAR)kernelBase) {
        matchDpc = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, dpcPattern, dpcMask);
    }
    if (matchDpc != NULL) {
        LONG disp = *(PLONG)(matchDpc + 3);
        PKDPC pPeriodicDpc = (PKDPC)(matchDpc + 7 + disp);

        if (MmIsAddressValid(pPeriodicDpc)) {
            // 缓存全局借壳对象地址, 供 DpcScannerRestoreBalanceSetManagerDpc 原样还原使用
            g_KiBalanceSetManagerPeriodicDpc = pPeriodicDpc;
            ULONG_PTR rva = (ULONG_PTR)pPeriodicDpc - (ULONG_PTR)kernelBase;
            PVOID routine = pPeriodicDpc->DeferredRoutine;
            PVOID context = pPeriodicDpc->DeferredContext;

            UNICODE_STRING modName = { 0 };
            ULONG_PTR routineOffset = 0;
            BOOLEAN found = KernelHelperFindModuleByAddress(routine, &modName, &routineOffset);
            PgReportFound(PgMethod5, PgSuspected, found ? NULL : routine, 0, NULL, "routine has no known module backing");

            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[Method 5] KiBalanceSetManagerPeriodicDpc: %p (ntoskrnl.exe+0x%llX)\n",
                pPeriodicDpc, (unsigned long long)rva));

            if (found) {
                PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "           -> DeferredRoutine: %p (%wZ+0x%llX)\n",
                    routine, &modName, (unsigned long long)routineOffset));
            } else {
                PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "           -> DeferredRoutine: %p [被篡改/挂钩到未知内存! 疑似PG Method 5]\n",
                    routine));
            }
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "           -> DeferredContext: %p (Canonical: %s), Type: %u, Importance: %u\n",
                context, KernelHelperIsCanonicalAddress(context) ? "YES" : "NO! (Method 0)",
                pPeriodicDpc->Type, pPeriodicDpc->Importance));
        }
    } else {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[Method 5] 未能匹配到 KiBalanceSetManagerPeriodicDpc 特征码\n"));
    }

    // -------------------------------------------------------------------------
    // 2. 独立检测例程 CcBcbProfiler (独立 Timer 轮询函数，每 2 分钟校验 NT 内核)
    // -------------------------------------------------------------------------
    PgReportErrorIf(PgMethod5, g_KiBalanceSetManagerPeriodicDpc == NULL, "periodic DPC not located/readable");
    PVOID pCcBcbProfiler = ResolveCcBcbProfiler();

    if (pCcBcbProfiler != NULL && MmIsAddressValid(pCcBcbProfiler)) {
        ULONG_PTR rva = (ULONG_PTR)pCcBcbProfiler - (ULONG_PTR)kernelBase;
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[Independent DPC] 函数 CcBcbProfiler 地址: %p (ntoskrnl.exe+0x%llX)\n",
            pCcBcbProfiler, (unsigned long long)rva));
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "                   -> 机制说明: 独立定时器双生例程之一 (每 2 分钟与 CcBcbProfiler2 轮询校验内核完整性)\n"
            "                   -> 绕过手段: 遍历定时器表命中后将其 Dpc 指针置空即可阻断\n"));
    } else {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[Independent DPC] 未能匹配到 CcBcbProfiler 特征码\n"));
    }

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "============================================================================\n\n"));
}

// -----------------------------------------------------------------------------
// 按 CPU 编号取 PRCB: ntoskrnl 导出 KeQueryPrcbAddress(ULONG) (WDK 头文件未声明,
// 动态解析)。避免了旧的逐 CPU KeSetSystemGroupAffinityThread 切换 —— 该切换
// 在虚拟化环境下每次可能触发 VM-exit/TLB flush, 是 M0 扫描耗时爆炸的主因。
// -----------------------------------------------------------------------------
static BOOLEAN g_PrcbResolverReady = FALSE;
PG_KE_QUERY_PRCB_ADDRESS g_KeQueryPrcbAddress = NULL;

VOID ResolvePrcbAddressRoutine(VOID)
{
    if (g_PrcbResolverReady) {
        return;
    }
    g_PrcbResolverReady = TRUE;

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"KeQueryPrcbAddress");
    g_KeQueryPrcbAddress = (PG_KE_QUERY_PRCB_ADDRESS)MmGetSystemRoutineAddress(&name);

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[DpcScanner] KeQueryPrcbAddress 解析: %p%s\n",
        g_KeQueryPrcbAddress,
        g_KeQueryPrcbAddress ? "" : " (不可用, M0 扫描降级为仅当前 CPU)"));
}

// 处理单个 PRCB 的完整检测 (原循环体; prcb 来自 KeQueryPrcbAddress 或当前 GSBASE)
static VOID DpcScannerInspectOneProcessor(
    _In_ ULONG CpuIndex,
    _In_ PUCHAR prcb,
    _In_ PDYNAMIC_OFFSETS offsets)
{
    // 1. 扫描该 CPU 核心上的 HalReserved 与 AcpiReserved (Method 1 & 2)
    DumpProcessorPatchGuardFields(CpuIndex, prcb);

    // 2. 读取动态偏移
    ULONG timerOffset = offsets->PrcbTimerTable;
    ULONG dpcDataOffset = offsets->PrcbDpcData;

    // 3. 扫描即时活动与排队 DPC
    PMY_KDPC_DATA dpcData = (PMY_KDPC_DATA)(prcb + dpcDataOffset);
    for (ULONG q = 0; q < 2; q++) {
        PKDPC active = dpcData[q].ActiveDpc;
        PgReportPartialIf(PgMethod0, active != NULL && !KernelHelperIsPageValidCached(active), "active DPC object unreadable");
        PgReportPartialIf(PgIndependentTimer, active != NULL && !KernelHelperIsPageValidCached(active), "active DPC object unreadable");
        if (active != NULL && KernelHelperIsPageValidCached(active)) {
            InspectDpcObject(active, "ActiveDpc", CpuIndex, 0, 0);
        }

        PSINGLE_LIST_ENTRY listEntry = dpcData[q].DpcList.ListHead.Next;
        ULONG listFuse = 0;
        while (listEntry != NULL && KernelHelperIsPageValidCached(listEntry) && listFuse++ < 1000000) {
            PKDPC dpc = CONTAINING_RECORD(listEntry, KDPC, DpcListEntry);
            InspectDpcObject(dpc, "QueuedDpc", CpuIndex, 0, 0);
            listEntry = listEntry->Next;
        }
        PgReportPartialIf(PgMethod0, listEntry != NULL, "DPC queue unreadable");
        PgReportPartialIf(PgIndependentTimer, listEntry != NULL, "DPC queue unreadable");
    }

    // 4. 扫描定时器表中的 DPC (KTIMER_TABLE，含 Method 0 与 CcBcbProfiler)
    PMY_KTIMER_TABLE timerTable = (PMY_KTIMER_TABLE)(prcb + timerOffset);
    ULONG timerDpcCount = 0;
    ULONG totalTimerCount = 0;

    for (ULONG hand = 0; hand < 2; hand++) {
        for (ULONG bucket = 0; bucket < 256; bucket++) {
            PLIST_ENTRY head = &timerTable->TimerEntries[hand][bucket].Entry;
            // 空桶快跳 (绝大多数桶为空): 先读 Flink —— TimerTable 驻留非分页池
            // 且 PRCB 指针来自内核自身, 无需每桶先做 MmIsAddressValid(head)。
            if (head->Flink == head) {
                continue; // 空桶 (双向链表 Flink==head 即空)
            }

            if (!KernelHelperIsPageValidCached(head)) {
                PgReportPartial(PgMethod0, "timer bucket unreadable");
                PgReportPartial(PgIndependentTimer, "timer bucket unreadable");
                continue;
            }
            if (head->Blink == head) {
                continue; // Flink 已离开 head 而 Blink 仍自指: 并发撕裂, 保守跳过
            }

            // 校验双向循环链表结构自洽性 (防越界与结构畸变)
            if (!KernelHelperIsPageValidCached(head->Flink) || !KernelHelperIsPageValidCached(head->Blink)) {
                PgReportPartial(PgMethod0, "timer chain link unreadable");
                PgReportPartial(PgIndependentTimer, "timer chain link unreadable");
                continue;
            }
            if (head->Flink->Blink != head || head->Blink->Flink != head) {
                PgReportPartial(PgMethod0, "timer chain inconsistent");
                PgReportPartial(PgIndependentTimer, "timer chain inconsistent");
                continue;
            }

            PLIST_ENTRY curr = head->Flink;

            ULONG chainFuse = 0;
            while (curr != head && curr != NULL && KernelHelperIsPageValidCached(curr) && chainFuse++ < 1000000) {
                PKTIMER timer = CONTAINING_RECORD(curr, KTIMER, TimerListEntry);
                if (!KernelHelperIsPageValidCached(timer)) {
                    break;
                }

                totalTimerCount++;

                ULONG_PTR rawDpcVal = (ULONG_PTR)timer->Dpc;
                if (rawDpcVal != 0) {
                    // 统一解码入口: 完整 Cookie 模型 -> 探针异或模型 -> 明文
                    PKDPC realDpc = DecodeTimerDpc(timer, NULL);
                    // 瞬态中间态不再重试等待: 10μs 退避在活系统定时器高频增删下
                    // 会累积; 下一轮复扫自然补偿。
                    PgReportPartialIf(PgMethod0, realDpc == NULL, "timer DPC not decoded/readable");
                    PgReportPartialIf(PgIndependentTimer, realDpc == NULL, "timer DPC not decoded/readable");

                    if (realDpc != NULL) {
                        timerDpcCount++;
                        InspectDpcObject(realDpc, "Timer-DPC", CpuIndex, timer->Period, timer->DueTime.QuadPart);
                    }
                }

                curr = curr->Flink;
            }
            PgReportPartialIf(PgMethod0, curr != head, "timer chain unreadable");
            PgReportPartialIf(PgIndependentTimer, curr != head, "timer chain unreadable");
        }
    }

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "  [CPU %02u] 定时器统计: 总活跃定时器 %u 个, 绑定 DPC 定时器 %u 个 (已解密)\n",
        CpuIndex, totalTimerCount, timerDpcCount));
}

VOID DpcScannerScanAllProcessors(VOID)
{
    ULONG totalCpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    PDYNAMIC_OFFSETS offsets = KernelHelperGetOffsets();

    // 预先反解内核随机加密 Cookie 及 CcBcbProfiler / CcBcbProfiler2 孪生例程入口
    ResolveKiWaitCookies();
    ResolveKiWaitNever();
    ResolveCcBcbProfiler();
    ResolveCcBcbProfiler2();
    ResolvePrcbAddressRoutine();
    PgReportErrorIf(PgIndependentTimer, g_CcBcbProfiler == NULL && g_CcBcbProfiler2 == NULL, "neither independent routine located");
    PgReportPartialIf(PgIndependentTimer, (g_CcBcbProfiler == NULL) != (g_CcBcbProfiler2 == NULL), "only one independent routine located");

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "==================== [DpcScanner 开始全系统 DPC 扫描 (无亲和切换)] ====================\n"
        "[DpcScanner] 检测到活动 CPU 核心数: %u | PRCB 解析: %s\n",
        totalCpus, g_KeQueryPrcbAddress ? "KeQueryPrcbAddress" : "降级 (仅当前 CPU)"));

    if (g_KeQueryPrcbAddress != NULL) {
        // 快路径: 按 CPU 编号直取 PRCB 指针, 纯内存读, 零亲和切换/零 VM-exit
        for (ULONG i = 0; i < totalCpus; i++) {
            PUCHAR prcb = (PUCHAR)g_KeQueryPrcbAddress(i);
            if (prcb == NULL || !KernelHelperIsPageValidCached(prcb)) {
                PgReportPartial(PgMethod0, "PRCB pointer unavailable for processor");
                PgReportPartial(PgMethod1, "PRCB pointer unavailable for processor");
                PgReportPartial(PgMethod2, "PRCB pointer unavailable for processor");
                PgReportPartial(PgIndependentTimer, "PRCB pointer unavailable for processor");
                continue;
            }
            DpcScannerInspectOneProcessor(i, prcb, offsets);
        }
    } else {
        // 降级路径: 仅扫描当前 CPU (不再做亲和切换 —— 慢且在 VM 下放大)
        PUCHAR prcb = (PUCHAR)__readgsqword(0x20);
        ULONG currentIndex = (ULONG)KeGetCurrentProcessorNumberEx(NULL);
        DpcScannerInspectOneProcessor(currentIndex, prcb, offsets);
        PgReportPartial(PgMethod0, "PrcbAddress resolver unavailable; scanned current CPU only");
        PgReportPartial(PgMethod1, "PrcbAddress resolver unavailable; scanned current CPU only");
        PgReportPartial(PgMethod2, "PrcbAddress resolver unavailable; scanned current CPU only");
        PgReportPartial(PgIndependentTimer, "PrcbAddress resolver unavailable; scanned current CPU only");
    }

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "==================== [DpcScanner 扫描结束] ====================\n\n"));
}
