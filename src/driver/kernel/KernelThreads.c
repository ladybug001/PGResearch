#include "KernelState.h"

VOID ResolveDynamicOffsets(VOID)
{
    // 初始化默认回退值 (基于 Win10/11 常见配置)
    g_Offsets.PrcbTimerTable = 0x3940;
    g_Offsets.PrcbDpcData    = 0x30C0;

    __try {
        // --- 动态验证 KPRCB.TimerTable ---
        PUCHAR prcb = (PUCHAR)__readgsqword(0x20);
        const ULONG timerCandidates[] = { 0x3940, 0x36C0, 0x3700, 0x3500, 0x4100, 0x3B40 };
        for (ULONG i = 0; i < sizeof(timerCandidates) / sizeof(timerCandidates[0]); i++) {
            ULONG cand = timerCandidates[i];
            PUCHAR tableBase = prcb + cand;

            // 检查前 16 个 bucket 的 Entry 链表自引用特征
            ULONG validBuckets = 0;
            for (ULONG b = 0; b < 16; b++) {
                ULONG_PTR entryOffset = (sizeof(ULONG_PTR) * 64) + (b * 32) + sizeof(ULONG_PTR);
                PLIST_ENTRY p = (PLIST_ENTRY)(tableBase + entryOffset);
                if (MmIsAddressValid(p)) {
                    if (p->Flink == p && p->Blink == p) {
                        validBuckets++;
                    } else if (MmIsAddressValid(p->Flink) && MmIsAddressValid(p->Blink) &&
                               p->Flink->Blink == p && p->Blink->Flink == p) {
                        validBuckets++;
                    }
                }
            }
            if (validBuckets >= 8) {
                g_Offsets.PrcbTimerTable = cand;
                break;
            }
        }

        g_Offsets.IsOffsetsResolved = TRUE;

        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[KernelHelper] 动态结构体自省完成: KPRCB.TimerTable=0x%X, DpcData=0x%X\n",
            g_Offsets.PrcbTimerTable, g_Offsets.PrcbDpcData));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[KernelHelper] 动态偏移自省过程出现异常，沿用原默认偏移\n"));
    }
}
