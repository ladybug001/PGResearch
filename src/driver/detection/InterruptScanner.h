#pragma once
#include <ntddk.h>
#include "Kernel.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 初始化软件中断与全局插桩扫描器
 */
VOID InterruptScannerInit(_In_ PDRIVER_OBJECT DriverObject);

/**
 * @brief 扫描并诊断 PatchGuard 软件中断与全局机制：
 *        1. Method 7 (KiSwInterruptDispatch 函数入口与全局 MaxDataSize 指针)
 *           - 重点分析并防御 [MaxDataSize + 0x648] 无条件解引用引发的 0x50/0x109 蓝屏陷阱
 *        2. KiMcaRecovery (Pg_KiMcaDeferredRecoveryService 独立轻量插桩下电跳板)
 */
VOID InterruptScannerScanGlobalHooks(VOID);

/**
 * @brief 获取已定位的 KiSwInterruptDispatch 函数入口地址
 */
PVOID InterruptScannerGetKiSwInterruptDispatchAddress(VOID);


#ifdef __cplusplus
}
#endif
