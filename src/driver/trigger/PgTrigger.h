#pragma once
#include <ntddk.h>
#include "Kernel.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 初始化主动触发模块
 */
VOID PgTriggerInit(_In_ PDRIVER_OBJECT DriverObject);

/**
 * @brief 挂钩 ntoskrnl.exe!RtlCompareMemory (快速触发 PatchGuard 0x109 校验和告警)
 *        - 使用 12 字节绝对跳转 (movabs rax, <trampoline>; jmp rax) 改变代码哈希
 *        - 在 Trampoline 跳板中原样执行搬迁的 Prologue 指令并跳回原函数下游
 *        - 沿用原跳板实现并改变 ntoskrnl.exe .text；不保证触发时机
 * 
 * @return BOOLEAN 操作是否成功
 */
BOOLEAN PgTriggerArmCode(VOID);

/**
 * @brief 撤销挂钩，恢复 RtlCompareMemory 原始指令
 */
VOID PgTriggerRestoreCode(VOID);

/**
 * @brief 查询当前挂钩激活状态与调用触发计数
 */
BOOLEAN PgTriggerIsActive(_Out_opt_ PULONG64 OutExecutionCount);

#ifdef __cplusplus
}
#endif
