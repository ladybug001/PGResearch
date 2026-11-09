#include "Bypass.h"
#include "InterruptState.h"

BOOLEAN InterruptScannerPatchKiSwInterruptDispatch(_In_ BOOLEAN Enable)
{
    if (g_KiSwInterruptDispatchAddress == NULL) {
        return FALSE;
    }

    if (Enable) {
        if (g_IsKiSwDispatchPatched) {
            return TRUE;
        }

        const UCHAR patchBytes[1] = { 0xC3 }; // ret
        BOOLEAN success = KernelHelperWriteReadOnlyMemory(g_KiSwInterruptDispatchAddress, patchBytes, sizeof(patchBytes));
        if (success) {
            g_IsKiSwDispatchPatched = TRUE;
            PgReportAction(PgMethod7, PgActionApplied, "original code patch applied");
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[InterruptScanner] [成功] 已对 KiSwInterruptDispatch (%p) 入口下发 0xC3 (ret) 热补丁！\n"
                "                   -> 成果: Method 7 软件中断派发被直接返回截断, 免疫 [MaxDataSize + 0x648] 解引用\n",
                g_KiSwInterruptDispatchAddress));
            return TRUE;
        } else {
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[InterruptScanner] [失败] 对 KiSwInterruptDispatch 写入热补丁失败\n"));
            PgReportAction(PgMethod7, PgActionFailed, "original code write failed");
            return FALSE;
        }
    } else {
        if (!g_IsKiSwDispatchPatched) {
            return TRUE;
        }

        BOOLEAN success = KernelHelperWriteReadOnlyMemory(g_KiSwInterruptDispatchAddress, g_OriginalKiSwDispatchBytes, sizeof(g_OriginalKiSwDispatchBytes));
        if (success) {
            g_IsKiSwDispatchPatched = FALSE;
            PgReportRestore(PgMethod7, PgRestored);
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[InterruptScanner] 已还原 KiSwInterruptDispatch (%p) 原始指令 (%02X)\n",
                g_KiSwInterruptDispatchAddress, g_OriginalKiSwDispatchBytes[0]));
            return TRUE;
        } else {
            PgReportRestore(PgMethod7, PgRestoreFailed);
            return FALSE;
        }
    }
}

BOOLEAN InterruptScannerPatchKiMcaRecovery(_In_ BOOLEAN Enable)
{
    if (g_KiMcaAddress == NULL) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[InterruptScanner] KiMcaDeferredRecoveryService 地址未定位，无法下发热补丁\n"));
        return FALSE;
    }

    if (Enable) {
        if (g_IsKiMcaPatched) {
            return TRUE;
        }

        const UCHAR patchBytes[2] = { 0xC3, 0xCC }; // ret; int3
        BOOLEAN success = KernelHelperWriteReadOnlyMemory(g_KiMcaAddress, patchBytes, sizeof(patchBytes));
        if (success) {
            g_IsKiMcaPatched = TRUE;
            PgReportAction(PgRecoveryPath, PgActionApplied, "original code patch applied");
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[InterruptScanner] [成功] 已对 KiMcaDeferredRecoveryService (%p) 下发 0xC3 (ret) 热补丁！\n"
                "                   -> 成果: 已阻断 PspProcessDelete、KiInitializeUserApc 等独立插桩的下电控制流！\n",
                g_KiMcaAddress));
            return TRUE;
        } else {
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[InterruptScanner] [失败] 对 KiMcaDeferredRecoveryService 写入补丁失败\n"));
            PgReportAction(PgRecoveryPath, PgActionFailed, "original code write failed");
            return FALSE;
        }
    } else {
        if (!g_IsKiMcaPatched) {
            return TRUE;
        }

        BOOLEAN success = KernelHelperWriteReadOnlyMemory(g_KiMcaAddress, g_OriginalKiMcaBytes, sizeof(g_OriginalKiMcaBytes));
        if (success) {
            g_IsKiMcaPatched = FALSE;
            PgReportRestore(PgRecoveryPath, PgRestored);
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[InterruptScanner] 已成功还原 KiMcaDeferredRecoveryService (%p) 原始指令 (%02X %02X)\n",
                g_KiMcaAddress, g_OriginalKiMcaBytes[0], g_OriginalKiMcaBytes[1]));
            return TRUE;
        } else {
            PgReportRestore(PgRecoveryPath, PgRestoreFailed);
            return FALSE;
        }
    }
}

BOOLEAN InterruptScannerDestroyContext7(VOID)
{

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "\n==================== [Method 7 主动处置 (DestroyContext7)] ====================\n"));

    // 0. 前置判定: Method 7 未激活时绝不触碰 KiSwInterruptDispatch。
    //    该函数是 DPC/APC/IPI 软件中断的公共派发入口 —— 入口 0xC3 截断会把
    //    整个软件中断派发打断: BarricadeArm 的 KeInvalidateAllCaches 等 IPI
    //    应答永远等不到, 未开 Barricade 时 DPC/定时器同样失能。
    //    实测: BypassEnabled 打开后无条件下发该补丁 => 加载阶段直接卡死。
    if (g_pMaxDataSize == NULL) {
        PgReportAction(PgMethod7, PgActionSkipped, "context location unavailable; dispatch patch withheld");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[Method 7] MaxDataSize 未定位, 不下发派发截断补丁 (Method 7 未激活, 避免打断软件中断)\n"));
        return TRUE;
    }

    __try {
        if (*g_pMaxDataSize == NULL) {
            PgReportAction(PgMethod7, PgActionNotNeeded, "context null; dispatch patch withheld");
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[Method 7] MaxDataSize 为 NULL (Method 7 未激活), 不下发派发截断补丁\n"));
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        PgReportAction(PgMethod7, PgActionFailed, "exception reading context pointer");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[Method 7] MaxDataSize 读取异常, 安全中止\n"));
        return FALSE;
    }

    // 1. Method 7 确实激活: 保持"先截断派发、后置零上下文"的次序 ——
    //    否则 KiSwInterruptDispatch 对 [MaxDataSize + 0x648] 的无判空解引用会蓝屏。
    if (g_KiSwInterruptDispatchAddress == NULL) {
        PgReportAction(PgMethod7, PgActionSkipped, "dispatch not located");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[Method 7] KiSwInterruptDispatch 入口未定位, 无法执行派发截断\n"));
        return FALSE;
    }

    if (!InterruptScannerPatchKiSwInterruptDispatch(TRUE)) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[Method 7] KiSwInterruptDispatch 截断补丁下发失败\n"));
        return FALSE;
    }

    // 2. 数据面处置: 上下文置零 (截断已就位, 置零安全)
    __try {
        PVOID currentContext = *g_pMaxDataSize;

        InterlockedExchangePointer(g_pMaxDataSize, NULL);
        PgReportAction(PgMethod7, PgActionApplied, "original context data write applied");
        PgReportRestore(PgMethod7, PgRestoreUnsupported);

        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[Method 7] [成功] MaxDataSize (%p) 已由 %p 置零! 已执行原有上下文写入操作\n",
            g_pMaxDataSize, currentContext));
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        PgReportAction(PgMethod7, PgActionFailed, "exception during original context operation");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[Method 7] MaxDataSize 置零过程发生访问违规, 安全中止\n"));
        return FALSE;
    }
}
