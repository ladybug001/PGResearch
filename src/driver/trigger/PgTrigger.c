#include "PgTrigger.h"

#define PG_TRIGGER_POOL_TAG 'grTP'
#define PG_HOOK_DETOUR_BYTES 12
#define PG_HOOK_TAIL_BYTES   14

static PDRIVER_OBJECT g_DriverObject = NULL;
static PUCHAR g_TargetFunction = NULL;
static UCHAR g_OriginalBytes[32] = { 0 };
static ULONG g_PrologueLength = 0;
static PUCHAR g_Trampoline = NULL;
static BOOLEAN g_IsHooked = FALSE;
static volatile ULONG64 g_TriggerCount = 0;

static ULONG CalculatePrologueBytes(_In_ const UCHAR* Function, _In_ ULONG RequiredMinBytes)
{
    ULONG total = 0;
    while (total < RequiredMinBytes && total < 32) {
        ULONG instLen = KernelHelperDecodeInstructionLength(Function + total);
        if (instLen == 0) {
            return 0;
        }
        total += instLen;
    }
    return total;
}

VOID PgTriggerInit(_In_ PDRIVER_OBJECT DriverObject)
{
    g_DriverObject = DriverObject;
}

BOOLEAN PgTriggerIsActive(_Out_opt_ PULONG64 OutExecutionCount)
{
    if (OutExecutionCount != NULL) {
        *OutExecutionCount = g_TriggerCount;
    }
    return g_IsHooked;
}

// -----------------------------------------------------------------------------
// 核心实施：挂钩 RtlCompareMemory
// -----------------------------------------------------------------------------
BOOLEAN PgTriggerArmCode(VOID)
{
    if (g_IsHooked) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[PgTrigger] 挂钩已处于激活状态，无需重复触发\n"));
        return TRUE;
    }

    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"RtlCompareMemory");
    g_TargetFunction = (PUCHAR)MmGetSystemRoutineAddress(&routineName);

    if (g_TargetFunction == NULL) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[PgTrigger] 未能解析到 ntoskrnl.exe!RtlCompareMemory 符号\n"));
        return FALSE;
    }

    // 1. 精确计算搬迁指令长度 (至少 12 字节)
    g_PrologueLength = CalculatePrologueBytes(g_TargetFunction, PG_HOOK_DETOUR_BYTES);
    if (g_PrologueLength < PG_HOOK_DETOUR_BYTES || g_PrologueLength > 32) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[PgTrigger] 无法安全搬迁目标函数 Prologue (计算长度: %u 字节)\n", g_PrologueLength));
        return FALSE;
    }

    // 2. 备份原始入口指令
    RtlCopyMemory(g_OriginalBytes, g_TargetFunction, g_PrologueLength);

    // 3. 分配非分页可执行内存 (Trampoline 跳板)
    ULONG trampolineSize = g_PrologueLength + PG_HOOK_TAIL_BYTES;
#pragma warning(suppress: 4996)
    g_Trampoline = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, trampolineSize, PG_TRIGGER_POOL_TAG);
    if (g_Trampoline == NULL) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[PgTrigger] 分配 Trampoline 执行池失败\n"));
        return FALSE;
    }

    // 4. 在 Trampoline 中构建：原样 Prologue 指令 + jmp qword ptr [rip+0] 返回原函数
    RtlCopyMemory(g_Trampoline, g_TargetFunction, g_PrologueLength);

    // jmp qword ptr [rip+0] (FF 25 00 00 00 00 <8字节目标地址>)
    ULONG tailOff = g_PrologueLength;
    g_Trampoline[tailOff + 0] = 0xFF;
    g_Trampoline[tailOff + 1] = 0x25;
    g_Trampoline[tailOff + 2] = 0x00;
    g_Trampoline[tailOff + 3] = 0x00;
    g_Trampoline[tailOff + 4] = 0x00;
    g_Trampoline[tailOff + 5] = 0x00;

    ULONG_PTR returnAddr = (ULONG_PTR)(g_TargetFunction + g_PrologueLength);
    RtlCopyMemory(g_Trampoline + tailOff + 6, &returnAddr, sizeof(returnAddr));

    // 5. 构建入口 Detour 补丁：movabs rax, <Trampoline>; jmp rax (48 B8 <addr> FF E0)
    UCHAR entryPatch[32] = { 0 };
    entryPatch[0] = 0x48;
    entryPatch[1] = 0xB8;
    ULONG_PTR trampAddr = (ULONG_PTR)g_Trampoline;
    RtlCopyMemory(&entryPatch[2], &trampAddr, sizeof(trampAddr));
    entryPatch[10] = 0xFF;
    entryPatch[11] = 0xE0;

    // 若搬迁长度大于 12 字节，填充 NOP (0x90)
    for (ULONG i = 12; i < g_PrologueLength; i++) {
        entryPatch[i] = 0x90;
    }

    // 6. 安全写入只读代码段 (通过 KernelHelper 的 MDL 双重映射机制)
    BOOLEAN writeOk = KernelHelperWriteReadOnlyMemory(g_TargetFunction, entryPatch, g_PrologueLength);
    if (!writeOk) {
        ExFreePoolWithTag(g_Trampoline, PG_TRIGGER_POOL_TAG);
        g_Trampoline = NULL;
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[PgTrigger] 对 RtlCompareMemory 写入 Detour 失败\n"));
        return FALSE;
    }

    g_IsHooked = TRUE;

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "\n==================== [!PG 显式触发通道已激活 (ARMED)!] ====================\n"
        "[PgTrigger] 目标函数: ntoskrnl.exe!RtlCompareMemory (%p)\n"
        "[PgTrigger] 搬迁长度: %u 字节 | 跳板地址: %p\n"
        "[PgTrigger] 挂钩手法: 12 字节绝对跳转 (movabs rax, tramp; jmp rax)\n"
        "[PgTrigger] 业务语义: 沿用原有跳板回跳实现，是否触发需实际观察\n"
        "[PgTrigger] 核心目的: 故意破坏 ntoskrnl.exe .text 代码段校验和，作为原有 PG 触发实验\n"
        "             -> 预估现象: 等待实际完整性检测结果，不保证触发时机\n"
        "             -> 蓝屏错误码: 0x109 (CRITICAL_STRUCTURE_CORRUPTION)\n"
        "===========================================================================\n\n",
        g_TargetFunction, g_PrologueLength, g_Trampoline));

    return TRUE;
}

// -----------------------------------------------------------------------------
// 撤销挂钩，恢复原始代码
// -----------------------------------------------------------------------------
VOID PgTriggerRestoreCode(VOID)
{
    if (!g_IsHooked || g_TargetFunction == NULL) {
        return;
    }

    BOOLEAN restoreOk = KernelHelperWriteReadOnlyMemory(g_TargetFunction, g_OriginalBytes, g_PrologueLength);
    if (restoreOk) {
        PgPrint("[RESTORE] Trigger | RESTORED\n");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[PgTrigger] 已成功恢复 RtlCompareMemory 原始指令！\n"));
    } else {
        PgPrint("[RESTORE] Trigger | FAILED; original resource-release behavior retained\n");
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[PgTrigger] 恢复 RtlCompareMemory 原始指令失败\n"));
    }

    if (g_Trampoline != NULL) {
        ExFreePoolWithTag(g_Trampoline, PG_TRIGGER_POOL_TAG);
        g_Trampoline = NULL;
    }

    g_IsHooked = FALSE;
}
