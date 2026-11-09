#include <ntifs.h>
#include <ntddk.h>
#include "ConfigRegistry.h"
#include "Kernel.h"
#include "DpcScanner.h"
#include "InterruptScanner.h"
#include "Bypass.h"
#include "Barricade.h"
#include "PgTrigger.h"

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    unsigned long i;
    UNREFERENCED_PARAMETER(DriverObject);

    PgReportReleaseTracking();

    // 1. 撤销 Barricade 通杀: 还原 MmAccessFault 原始指令并恢复页面执行权
    BarricadeDisarm();

    // 2. 若激活了 PG 快速触发挂钩，在卸载前安全恢复原始指令并释放跳板
    PgTriggerRestoreCode();

    // 3. 若应用了 KiSw / KiMca 热补丁，安全还原原始指令
    InterruptScannerPatchKiSwInterruptDispatch(FALSE);
    InterruptScannerPatchKiMcaRecovery(FALSE);

    // 4. 关键防护：排空并等待系统中所有尚未完成的 DPC 队列，防卸载后执行游离指针
    KeFlushQueuedDpcs();

    // 5. 输出卸载摘要
    PgPrint("[Unload] 驱动已安全卸载\n");
    PgPrint("[Unload] 提示: 定时器/PRCB/Timeout 覆写等操作不具备完整还原能力 (仅限研究环境演示)\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    PG_CONFIG config;
    NTSTATUS status;
    ULONG i;
    ULONGLONG runId = KeQueryInterruptTime();
    PgConfigDefaults(&config);
    PgReportInitialize(&config, runId);
    if (!NT_SUCCESS((status = PgConfigLoad(RegistryPath, &config)))) {
        PgPrintErr("[Config] 配置加载失败: 0x%08X, 未执行任何特性\n", status);
        return status;
    }
    PgReportInitialize(&config, runId);
    PgReportPrintConfiguration();
    if (config.TriggerEnabled && config.BypassEnabled) PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[Config] 组合实验：先检测及绕过，输出报告后再设置触发。\n"));

    DriverObject->DriverUnload = DriverUnload;
    KernelHelperInit(DriverObject);
    BarricadeMarkSelfImage(DriverObject); // 布防安全自检: 识别自身镜像, 防摘权自裁
    DpcScannerInit(DriverObject);
    InterruptScannerInit(DriverObject);

    if (config.ScanEnabled) {
        for (i = 0; i < PgItemCount; ++i) {
            if (i == PgMethod3 || i == PgMethod4 || i == PgMethod6) continue;
            PgReportBegin((PG_ITEM_ID)i);
            PgReportGetItem((PG_ITEM_ID)i)->Started = KeQueryInterruptTime();
        }
        InterruptScannerScanGlobalHooks();
        DpcScannerDumpGlobalDpcStructures();
        DpcScannerScanAllProcessors();      // M0/M1/M2 定时器与 DPC 扫描
        BarricadeScan();                   // RWX 内存扫描 (针对 Pool 与 Independent 页面)
        for (i = 0; i < PgItemCount; ++i) {
            if (i == PgMethod3 || i == PgMethod4 || i == PgMethod6) continue;
            PgReportEnd((PG_ITEM_ID)i);
            PgReportGetItem((PG_ITEM_ID)i)->Finished = KeQueryInterruptTime();
        }
        PgReportPrint();
    } else {
        PgPrint("[Config] ScanEnabled=0: 已跳过静态/调度特征扫描。\n");
    }

    // 综合绕过: 包含 Barricade 通杀 (针对 Method 3/4 及未背书 RWX 页) + 结构体主动处置/热补丁 (针对 Method 0/1/2/5/7/Indep)
    if (config.BypassEnabled) {
        PgRunBypass();
        BarricadeArm();
    }

    PgTriggerInit(DriverObject);
    if (config.TriggerEnabled) {
        BOOLEAN armed = PgTriggerArmCode();
        if (armed) {
            PgPrint("[Trigger] 触发实验已设置（修改拷贝函数等待快速触发检测）\n");
        } else {
            PgPrintErr("[Trigger] 触发实验设置失败，详见详细日志\n");
        }
    }

    return STATUS_SUCCESS;
}
