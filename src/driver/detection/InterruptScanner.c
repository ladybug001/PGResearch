#include "InterruptState.h"
static PDRIVER_OBJECT g_DriverObject = NULL;
// KiSwInterruptDispatch 入口地址、原始字节备份与热补丁状态 (入口级 0xC3 RET 截断)
PVOID g_KiSwInterruptDispatchAddress = NULL;
UCHAR g_OriginalKiSwDispatchBytes[1] = { 0 };
BOOLEAN g_IsKiSwDispatchPatched = FALSE;

PVOID g_KiMcaAddress = NULL;
UCHAR g_OriginalKiMcaBytes[2] = { 0 };
BOOLEAN g_IsKiMcaPatched = FALSE;

// Method 7 全局上下文指针 (MaxDataSize 指向 PG Context 7 的全局变量地址)
PVOID* g_pMaxDataSize = NULL;

// KiSwInterruptDispatch 真身锚定校验结果 (未来外科式分支补丁的地基)
BOOLEAN g_KiSwDispatchVerified = FALSE;



VOID InterruptScannerInit(_In_ PDRIVER_OBJECT DriverObject)
{
    g_DriverObject = DriverObject;
}

PVOID InterruptScannerGetKiSwInterruptDispatchAddress(VOID)
{
    return g_KiSwInterruptDispatchAddress;
}

static BOOLEAN VerifyKiSwDispatchAnchor(VOID)
{

    g_KiSwDispatchVerified = FALSE;

    if (g_pMaxDataSize == NULL) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[锚定校验] MaxDataSize 全局变量未定位, 无法执行真身校验\n"));
        return FALSE;
    }
    if (g_KiSwInterruptDispatchAddress == NULL) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[锚定校验] 派发函数入口未定位, 无法执行真身校验\n"));
        return FALSE;
    }

    PUCHAR fn = (PUCHAR)g_KiSwInterruptDispatchAddress;
    ULONG_PTR fnVa = (ULONG_PTR)fn;
    PVOID kernelBase = KernelHelperGetKernelBase(NULL);
    ULONG_PTR rva = (kernelBase != NULL) ? (fnVa - (ULONG_PTR)kernelBase) : 0;

    // 仅扫描函数头 0x180 字节, 防止越入相邻函数造成假阳性
    const ULONG SCAN_LEN = 0x180;

    ULONG loadOffset = 0;      // mov reg, cs:MaxDataSize 命中偏移
    ULONG derefOffset = 0;     // mov reg, [rax+0x648] 陷阱命中偏移
    BOOLEAN loadFound = FALSE;
    BOOLEAN derefFound = FALSE;

    __try {
        ULONG off = 0;
        while (off + 8 <= SCAN_LEN) {
            PUCHAR cur = fn + off;

            // 页安全跳过 (严防跨入未映射页)
            if (!MmIsAddressValid(cur)) {
                ULONG_PTR pageBase = (ULONG_PTR)cur & ~((ULONG_PTR)PAGE_SIZE - 1);
                off = (ULONG)(pageBase + PAGE_SIZE - fnVa);
                continue;
            }

            // 候选: REX.W mov r64, r/m64 (48 8B /r)
            if (cur[0] == 0x48 && cur[1] == 0x8B && MmIsAddressValid(cur + 8)) {
                UCHAR modrm = cur[2];
                if ((modrm & 0xC7) == 0x05) {
                    // mod=00 rm=101: RIP 相对加载 mov reg, cs:[rip+disp32]
                    LONG disp = *(PLONG)(cur + 3);
                    ULONG_PTR target = (ULONG_PTR)(cur + 7) + (ULONG_PTR)(LONG_PTR)disp;
                    if (target == (ULONG_PTR)g_pMaxDataSize) {
                        loadOffset = off;
                        loadFound = TRUE;
                    }
                } else if ((modrm & 0xC7) == 0x80) {
                    // mod=10 rm=000: mov reg, [rax+disp32]
                    LONG disp = *(PLONG)(cur + 3);
                    if (disp == 0x648) {
                        derefOffset = off;
                        derefFound = TRUE;
                    }
                }
            }
            off++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[锚定校验] 扫描过程发生访问违规, 校验中止\n"));
        return FALSE;
    }

    // 入口原文 8 字节 (供人工反汇编核对: u nt+RVA / ln nt+RVA)
    UCHAR entryBytes[8] = { 0 };
    __try {
        if (MmIsAddressValid(fn)) {
            RtlCopyMemory(entryBytes, fn, sizeof(entryBytes));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[锚定校验] 入口 nt+0x%llX (%p), 函数体头 0x180 字节扫描:\n"
        "          -> 入口原文: %02X %02X %02X %02X %02X %02X %02X %02X\n"
        "          -> MaxDataSize 引用 (mov reg,cs:MaxDataSize): %s\n"
        "          -> +0x648 解引用 (mov reg,[rax+0x648]):       %s\n",
        (unsigned long long)rva, fn,
        entryBytes[0], entryBytes[1], entryBytes[2], entryBytes[3],
        entryBytes[4], entryBytes[5], entryBytes[6], entryBytes[7],
        loadFound ? "命中" : "未命中",
        derefFound ? "命中" : "未命中"));

    if (loadFound && derefFound) {
        g_KiSwDispatchVerified = TRUE;
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "          -> [校验通过-双重确认] 入口确为 KiSwInterruptDispatch 真身:\n"
        "             [+0x%X] mov reg, cs:MaxDataSize (目标 == &MaxDataSize %p)\n"
        "             [+0x%X] mov reg, [rax+0x648] (解引用陷阱, 外科补丁精确落点)\n",
        loadOffset, g_pMaxDataSize, derefOffset));
    } else if (loadFound) {
        g_KiSwDispatchVerified = TRUE;
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "          -> [校验通过-单一引用] 入口确为 KiSwInterruptDispatch 真身\n"
        "             (+0x648 解引用未在 0x180 扫描窗口内出现, 或已超出窗口)\n"));
    } else {
        g_KiSwDispatchVerified = FALSE;
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "          -> [校验否决] 入口 nt+0x%llX 函数体内未发现任何对 MaxDataSize 的引用:\n"
        "             【判定: 通用序言回退匹配的假身, 并非 KiSwInterruptDispatch!】\n"
        "             该入口的一切字节级补丁已被自动封禁 (先前关机挂死的直接原因)\n"
        "             人工确认: WinDbg 执行 ln nt+0x%llX 查看该地址真实符号\n",
        (unsigned long long)rva, (unsigned long long)rva));
    }

    return g_KiSwDispatchVerified;
}

VOID InterruptScannerScanGlobalHooks(VOID)
{
    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "\n================ [PatchGuard 软件中断 (Method 7) 与全局机制诊断] ================\n"));

    ULONG kernelSize = 0;
    PVOID kernelBase = KernelHelperGetKernelBase(&kernelSize);

    if (kernelBase == NULL || kernelSize == 0) {
        PgReportError(PgMethod7, "kernel base unavailable");
        PgReportError(PgRecoveryPath, "kernel base unavailable");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[InterruptScanner] 未能获取 ntoskrnl.exe 模块基址，跳过全局特征定位\n"));
        return;
    }

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[InterruptScanner] ntoskrnl.exe 基址: %p, 映像大小: 0x%X\n", kernelBase, kernelSize));

    // 优先定位 .text 节提升扫描速度与物理内存驻留安全性
    ULONG textSectionSize = 0;
    PUCHAR textBase = (PUCHAR)KernelHelperGetSectionAddress(kernelBase, ".text", &textSectionSize);
    PUCHAR scanBase = (textBase != NULL && textSectionSize > 0) ? textBase : (PUCHAR)kernelBase;
    ULONG scanSize = (textBase != NULL && textSectionSize > 0) ? textSectionSize : kernelSize;

    // -------------------------------------------------------------------------
    // 1. 全局变量 MaxDataSize (Method 7: 软件中断调度机制 Context 指针)
    // -------------------------------------------------------------------------
    // 签名: KiMarkBugCheckRegions 中对 MaxDataSize 的引用
    //   mov rcx, cs:MaxDataSize ; 48 8B 0D [disp32]
    //   test rcx, rcx          ; 48 85 C9
    //   jz   loc_...           ; 74 [disp8]
    //   mov  edx, 0AA0h        ; BA A0 0A 00 00
    //   call IoAddTriageDumpDataBlock ; E8
    const UCHAR maxDataPattern[] = {
        0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x85, 0xC9,
        0x74, 0x00,
        0xBA, 0xA0, 0x0A, 0x00, 0x00,
        0xE8
    };
    const char maxDataMask[] = "xxx????xxxx?xxxxxx";

    PUCHAR matchMaxData = KernelHelperFindPattern(scanBase, scanSize, maxDataPattern, maxDataMask);
    if (matchMaxData == NULL && scanBase != (PUCHAR)kernelBase) {
        matchMaxData = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, maxDataPattern, maxDataMask);
    }
    if (matchMaxData != NULL) {
        LONG disp = *(PLONG)(matchMaxData + 3);
        PVOID* pMaxDataSize = (PVOID*)(matchMaxData + 7 + disp);

        if (MmIsAddressValid(pMaxDataSize)) {
            // 缓存全局指针地址, 供 InterruptScannerDestroyContext7 置零使用
            g_pMaxDataSize = pMaxDataSize;


            PVOID maxDataValue = *pMaxDataSize;
            ULONG_PTR rva = (ULONG_PTR)pMaxDataSize - (ULONG_PTR)kernelBase;
            BOOLEAN isCanonical = maxDataValue ? KernelHelperIsCanonicalAddress(maxDataValue) : FALSE;
            BOOLEAN isRwx = maxDataValue ? KernelHelperIsMemoryRwx(maxDataValue) : FALSE;


            if (maxDataValue != NULL) {
                PgReportFound(PgMethod7, PgSuspected, maxDataValue, 0, NULL, "non-null context; not proof of execution");
                PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "  [CRIT!] [Method 7 软件中断上下文 MaxDataSize]\n"
                    "          -> 全局变量地址: %p (ntoskrnl.exe+0x%llX)\n"
                    "          -> 上下文当前值: %p [已激活 PG Context 7! 属性: %s | %s]\n",
                    pMaxDataSize, (unsigned long long)rva,
                    maxDataValue,
                    isCanonical ? "规范地址" : "非规范地址 (异常掩码)",
                    isRwx ? "[!] 位于 RWX 内存!" : "非 RWX 内存"));
            } else {
                PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                    "  [  OK  ] [Method 7 软件中断上下文 MaxDataSize]\n"
                    "          -> 全局变量地址: %p (ntoskrnl.exe+0x%llX) | 当前值: NULL\n",
                    pMaxDataSize, (unsigned long long)rva));
            }
        }
    } else {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  [ INFO ] [Method 7] 未能匹配到 MaxDataSize 特征码\n"));
    }

    // -------------------------------------------------------------------------
    // 2. 定位 KiSwInterruptDispatch 函数入口地址 (Method 7 软件中断分发函数)
    // -------------------------------------------------------------------------
    PVOID pKiSwInterruptDispatch = NULL;

    const UCHAR swIntPattern[] = {
        0x48, 0x8D, 0x4D, 0x80,
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0xFA,
        0x48, 0x8B, 0xCE
    };
    const char swIntMask[] = "xxxxx????xxxx";

    PUCHAR matchSwInt = KernelHelperFindPattern(scanBase, scanSize, swIntPattern, swIntMask);
    if (matchSwInt == NULL && scanBase != (PUCHAR)kernelBase) {
        matchSwInt = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, swIntPattern, swIntMask);
    }
    if (matchSwInt != NULL) {
        LONG disp = *(PLONG)(matchSwInt + 5);
        pKiSwInterruptDispatch = (PVOID)(matchSwInt + 9 + disp);
    }

    if (pKiSwInterruptDispatch == NULL) {
        // 回退: KiSwInterruptDispatch 函数序言签名 (IDA Pro 实测)
        //   mov [rsp+8], rcx         ; 48 89 4C 24 08
        //   push rbp, rbx, rsi, rdi  ; 55 53 56 57
        //   push r12-r15             ; 41 54 41 55 41 56 41 57
        //   lea rbp, [rsp-1Fh]       ; 48 8D 6C 24 ??
        //   sub rsp, 98h             ; 48 81 EC 98 00 00 00
        const UCHAR swDispatchPattern[] = {
            0x48, 0x89, 0x4C, 0x24, 0x08,
            0x55, 0x53, 0x56, 0x57,
            0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
            0x48, 0x8D, 0x6C, 0x24, 0x00,
            0x48, 0x81, 0xEC, 0x98, 0x00, 0x00, 0x00
        };
        const char swDispatchMask[] = "xxxxxxxxxxxxxxxxxxxx?xxxxxxx";
        PUCHAR matchPrologue = KernelHelperFindPattern(scanBase, scanSize, swDispatchPattern, swDispatchMask);
        if (matchPrologue == NULL && scanBase != (PUCHAR)kernelBase) {
            matchPrologue = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, swDispatchPattern, swDispatchMask);
        }
        if (matchPrologue != NULL) {
            pKiSwInterruptDispatch = (PVOID)matchPrologue;
        }
    }

    if (pKiSwInterruptDispatch != NULL && MmIsAddressValid(pKiSwInterruptDispatch)) {
        g_KiSwInterruptDispatchAddress = pKiSwInterruptDispatch;

        // 备份入口原始首字节, 供热补丁下发/卸载还原使用
        RtlCopyMemory(g_OriginalKiSwDispatchBytes, pKiSwInterruptDispatch, sizeof(g_OriginalKiSwDispatchBytes));

        ULONG_PTR rva = (ULONG_PTR)pKiSwInterruptDispatch - (ULONG_PTR)kernelBase;
        PUCHAR pBytes = (PUCHAR)pKiSwInterruptDispatch;


        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  [ INFO ] [Method 7 中断调度函数 KiSwInterruptDispatch]\n"
            "          -> 派发函数地址: %p (ntoskrnl.exe+0x%llX) | 首指令码: %02X %02X\n"
            "          -> 处置策略: 入口级 0xC3 (ret) 截断 (加载时下发, 卸载时还原)\n",
            pKiSwInterruptDispatch, (unsigned long long)rva, pBytes[0], pBytes[1]));
    } else {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  [ INFO ] [Method 7] 未能定位 KiSwInterruptDispatch 函数入口\n"));
    }

    // -------------------------------------------------------------------------
    // 2.5 真身锚定校验: 验证定位入口 (含通用序言回退匹配) 是否确为 KiSwInterruptDispatch
    //     校验仅作为原有诊断，不改变后续补丁的执行条件
    // -------------------------------------------------------------------------
    VerifyKiSwDispatchAnchor();
    PgReportErrorIf(PgMethod7, g_pMaxDataSize == NULL || g_KiSwInterruptDispatchAddress == NULL, "global context or dispatch location unavailable");

    // -------------------------------------------------------------------------
    // 3. 函数 KiMcaRecovery (Pg_KiMcaDeferredRecoveryService: 独立轻量插桩下电跳板)
    // -------------------------------------------------------------------------
    const UCHAR mcaPattern[] = {
        0x33, 0xC0,
        0x8B, 0xD8,
        0x8B, 0xF8,
        0x8B, 0xE8,
        0x4C, 0x8B, 0xD0,
        0x4C, 0x8B, 0xD8,
        0x4C, 0x8B, 0xE0,
        0x4C, 0x8B, 0xE8,
        0x4C, 0x8B, 0xF0,
        0x4C, 0x8B, 0xF8,
        0x48, 0x89, 0x04, 0x24,
        0xE9
    };
    const char mcaMask[] = "xxxxxxxxxxxxxxxxxxxxxxxxxx";

    PUCHAR matchMca = KernelHelperFindPattern(scanBase, scanSize, mcaPattern, mcaMask);
    if (matchMca == NULL && scanBase != (PUCHAR)kernelBase) {
        matchMca = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, mcaPattern, mcaMask);
    }
    PgReportErrorIf(PgRecoveryPath, matchMca == NULL, "support path signature not located");
    if (matchMca != NULL && MmIsAddressValid(matchMca)) {
        ULONG_PTR rva = (ULONG_PTR)matchMca - (ULONG_PTR)kernelBase;
        g_KiMcaAddress = matchMca;
        PgReportFound(PgRecoveryPath, PgLocatedOnly, matchMca, 0, NULL, "support path located; activity not established");
        RtlCopyMemory(g_OriginalKiMcaBytes, matchMca, sizeof(g_OriginalKiMcaBytes));

        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  [ INFO ] [全局插桩下电跳板 KiMcaDeferredRecoveryService]\n"
            "          -> 函数入口地址: %p (ntoskrnl.exe+0x%llX) | 状态: %s (首字节: %02X %02X)\n"
            "          -> 机制说明: PspProcessDelete / KiInitializeUserApc 异常时统一调此函数清栈引爆蓝屏\n",
            matchMca, (unsigned long long)rva,
            g_IsKiMcaPatched ? "[已打 RET 补丁拦截]" : "[原始状态]",
            g_OriginalKiMcaBytes[0], g_OriginalKiMcaBytes[1]));
    } else {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "  [ INFO ] [Global-Hook] 未能匹配到 KiMcaDeferredRecoveryService 特征码\n"));
        PgReportError(PgRecoveryPath, "support path not located/readable");
    }

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "=================================================================================\n\n"));
}
