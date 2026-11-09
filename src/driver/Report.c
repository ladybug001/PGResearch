#include "Log.h"
#include <ntstrsafe.h>

void PgPrint(PCSTR Format, ...)
{
    CHAR prefix[80];
    va_list args;
    if (PgReportConfig()->LogLevel)
        RtlStringCbPrintfA(prefix, sizeof(prefix), "[PgResearch][%I64u] ", PgReportRunId());
    else
        RtlStringCbPrintfA(prefix, sizeof(prefix), "[PgResearch] ");
    va_start(args, Format);
    vDbgPrintExWithPrefix(prefix, DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, args);
    va_end(args);
}
void PgPrintErr(PCSTR Format, ...)
{
    CHAR prefix[80];
    va_list args;
    if (PgReportConfig()->LogLevel)
        RtlStringCbPrintfA(prefix, sizeof(prefix), "[PgResearch][%I64u][ERROR] ", PgReportRunId());
    else
        RtlStringCbPrintfA(prefix, sizeof(prefix), "[PgResearch][ERROR] ");
    va_start(args, Format);
    vDbgPrintExWithPrefix(prefix, DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, args);
    va_end(args);
}
void PgTracePrint(ULONG Component, ULONG Level, PCSTR Format, ...)
{
    CHAR prefix[96];
    va_list args;
    UNREFERENCED_PARAMETER(Component);
    if (!PgReportConfig()->LogLevel) return;
    RtlStringCbPrintfA(prefix, sizeof(prefix), "[PgResearch][%I64u][DETAIL:%s] ", PgReportRunId(),
        Level == DPFLTR_WARNING_LEVEL ? "WARN" : Level == DPFLTR_ERROR_LEVEL ? "ERROR" : "INFO");
    va_start(args, Format);
    vDbgPrintExWithPrefix(prefix, DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, args);
    va_end(args);
}
typedef struct _PG_REPORT_ROW {
    PG_ITEM_ID Id;
    PCSTR Key, CheckObject, Probability;
} PG_REPORT_ROW;

/* Display mapping follows the analyzed kernel. Internal historical IDs stay unchanged. */
static const PG_REPORT_ROW g_Rows[] = {
    { PgMethod0, "0", "每个 CPU 的定时器 DPC（KTIMER.Dpc）", "20%左右" },
    { PgMethod2, "1", "每个 CPU 的 ACPI DPC 槽（KPRCB.AcpiReserved）", "20%左右" },
    { PgMethod1, "2", "每个 CPU 的 HAL 保留槽（HalReserved[7]）", "20%左右" },
    { PgMethod3, "3", "等待线程调用栈·非交集（等待函数命中，无 APC 派发帧）", "4%左右" },
    { PgMethod4, "4", "等待线程调用栈·交集（等待函数命中 + APC 派发帧）", "20%左右" },
    { PgMethod5, "5", "平衡集管理器的周期 DPC 对象（KiBalanceSetManagerPeriodicDpc）", "4%左右" },
    { PgMethod7, "7", "全局上下文指针 MaxDataSize 和派发入口 KiSwInterruptDispatch", "20%左右" },
    { PgIndependentTimer, "Independent1", "独立定时器的 DPC 例程（CcBcbProfiler / CcBcbProfiler2）", "不确定" },
    { PgRecoveryPath, "Independent2", "轻量校验相关蓝屏例程（KiMcaDeferredRecoveryService）", "不确定" }
};

static PCSTR SummaryCoverage(PG_COVERAGE Coverage)
{
    switch (Coverage) {
    case PgComplete: return "完整";
    case PgPartial: return "不完整*";
    case PgFailed: return "失败*";
    case PgUnsupported: return "未支持";
    default: return "未执行";
    }
}

static void SummaryObservation(const PG_ITEM_RESULT *Result, CHAR *Buffer, SIZE_T Size)
{
    if (Result->Coverage == PgNotRun || Result->Coverage == PgUnsupported) {
        RtlStringCbPrintfA(Buffer, Size, "未检测");
        return;
    }
    switch (Result->Observation) {
    case PgSuspected: RtlStringCbPrintfA(Buffer, Size, "疑似(%lu)", Result->Matches); break;
    case PgObservedActive: RtlStringCbPrintfA(Buffer, Size, "活跃(%lu)", Result->Matches); break;
    case PgLocatedOnly: RtlStringCbPrintfA(Buffer, Size, "定位到函数"); break;
    case PgNoMatch: RtlStringCbPrintfA(Buffer, Size, "未检出"); break;
    default: RtlStringCbPrintfA(Buffer, Size, "无法判断"); break;
    }
}


void PgReportPrintConfiguration(void)
{
    const PG_CONFIG *c = PgReportConfig();
    PgPrint("[Config] 检测=%s | 绕过=%s | 触发=%s | 输出=%s\n",
        c->ScanEnabled ? "开启" : "关闭", c->BypassEnabled ? "开启" : "关闭",
        c->TriggerEnabled ? "开启" : "关闭", c->LogLevel ? "详细" : "摘要");
}

void PgReportPrint(void)
{
    ULONG i;
    const PG_CONFIG *c = PgReportConfig();
    PgPrint("------------------------------ PG 原生检测机制盘点 ------------------------------\n");
    PgPrint("| %-13s | %-64s | %-9s | %-12s | %s\n", "方法", "检查对象", "存在概率", "本次检测", "扫描覆盖");
    for (i = 0; i < sizeof(g_Rows) / sizeof(g_Rows[0]); ++i) {
        const PG_REPORT_ROW *row = &g_Rows[i];
        PG_ITEM_RESULT *r = PgReportGetItem(row->Id);
        CHAR observation[48];
        SummaryObservation(r, observation, sizeof(observation));
        PgPrint("| %-13s | %-64s | %-9s | %-12s | %s\n", row->Key, row->CheckObject, row->Probability, observation, SummaryCoverage(r->Coverage));
    }
    PgPrint("---------------------------------------------------------------------------------\n");
    if (!c->LogLevel) return;
    const unsigned long *rwx = PgReportRwxCounts();
    if (rwx[0]) {
        PgPrint("扩展RWX：%s | 共%lu块，未归属模块%lu块，模块归属%lu块，跳过%lu项，异常%lu次。\n",
            rwx[0] == 2 ? "不完整" : "完成", rwx[1], rwx[2], rwx[3], rwx[4], rwx[5]);
    }
    for (i = 0; i < sizeof(g_Rows) / sizeof(g_Rows[0]); ++i) {
        const PG_REPORT_ROW *row = &g_Rows[i];
        PG_ITEM_RESULT *r = PgReportGetItem(row->Id);
        ULONG j;
        PgPrint("[详情:%s] coverage=%s observation=%s scanned=%lu matches=%lu locations=%lu retained=%lu dropped=%lu\n", row->Key, PgReportCoverageName(r->Coverage), PgReportObservationName(r->Observation), r->Scanned, r->Matches, r->Located, r->SampleCount, r->SamplesDropped);
        PgPrint("[证据:%s] %s | coverage=%s\n", row->Key, r->ObservationReason, r->CoverageReason);
        if (c->BypassEnabled) PgPrint("[操作:%s] %s changes=%lu failures=%lu skipped=%lu | %s | verification=NOT_RUN restore=%s\n", row->Key, PgReportActionName(r->Action), r->Applied, r->ActionFailures, r->ActionSkipped, r->ActionReason, PgReportRestoreName(r->Restore));
        PgPrint("[区间:%s] %I64u..%I64u (100ns, whole detection phase)\n", row->Key, r->Started, r->Finished);
        for (j = 0; j < r->SampleCount; ++j) {
            PG_EVIDENCE *e = &r->Samples[j];
            PgPrint("[样本:%s] object=%p group=0 cpu=%lu tid=%p | %s\n", row->Key, e->Object, e->Cpu, e->Tid, e->Reason);
        }
    }
}
