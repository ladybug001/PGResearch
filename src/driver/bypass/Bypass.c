#include "Bypass.h"
#include "Log.h"

VOID PgRunBypass(VOID)
{
    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[BYPASS] enabled; 主动处置开始 (载体 -> 线程/APC -> 数据 -> 代码补丁)\n"));

    // 1. 载体层：定时器 Dpc 置空 (Method 0 / CcBcb 独立轮询) + PRCB 保留槽位清空 (Method 1 / 2)。
    //    先掐灭一切调度载体，避免后续操作落在仍活跃的巡检窗口里。
    DpcScannerNeutralizeAllProcessors();

    // 2. 执行层：PG 系统线程 (Method 3) 与 APC (Method 4) 统一由 Barricade 硬件级缺页拦截接管
    //    (页面置 NX + 取指缺页捕获 + 重定向 KeDelayExecutionThread 长超时)
    PgReportAction(PgMethod3, PgActionApplied, "neutralized by Barricade (NX page-fault redirect)");
    PgReportAction(PgMethod4, PgActionApplied, "neutralized by Barricade (NX page-fault redirect)");
    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[BYPASS] Method 3/4 执行实体由 Barricade 缺页重定向统一接管处置\n"));

    // 3. 数据层：Method 5 全局借壳 KiBalanceSetManagerPeriodicDpc 原样还原
    DpcScannerRestoreBalanceSetManagerDpc();

    // 4. 代码层：ntoskrnl 代码补丁统一最后下发，尽量缩短代码段被改写的暴露窗口，
    //    降低被仍活跃的 PG Context 校验清单捕获的风险。
    //    内部必须保持 派发截断 -> MaxDataSize 置零 的次序：
    //    否则 KiSwInterruptDispatch 对 [MaxDataSize + 0x648] 的无判空解引用会直接蓝屏。
    InterruptScannerPatchKiMcaRecovery(TRUE);
    InterruptScannerDestroyContext7();

    PgPrint("[Bypass] 针对性处置已生效: M0/M1/M2/Indep1 定时器与DPC脱钩已完成 | M5平衡集放行 | M7/Indep2热补丁已就绪\n");
}
