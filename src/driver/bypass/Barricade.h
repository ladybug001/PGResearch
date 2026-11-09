#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 识别本驱动镜像范围 (幂等, DriverEntry 早期调用):
 *        kdmapper 手工映射镜像不在 PsLoadedModuleList (无模块背书),
 *        若不排除, 摘权会命中本驱动自身代码页, 钩子页缺页引发 detour
 *        无限递归 => 整机硬卡死。识别失败时 BarricadeArm 拒绝布防。
 * @param DriverObject 可空; DriverStart 无效时回退为从自身函数地址向下扫 PE 头
 */
VOID BarricadeMarkSelfImage(_In_opt_ PDRIVER_OBJECT DriverObject);

/**
 * @brief RWX 内存扫描 (检测阶段, 无条件执行):
 *        全内核 PTE 遍历收集未背书 RWX 页 (PG Context 唯一特征), 逐页报入 Barricade 行
 * @return 收集到的未背书 RWX 页数
 */
ULONG BarricadeScan(VOID);

/**
 * @brief 启用 Barricade 通杀:
 *        1. 收集未背书 RWX 页 (PG Context 唯一特征)
 *        2. 摘除执行权 (置 PTE.NX) —— PG 例程下次执行触发取指缺页
 *        3. Detour MmAccessFault: 取指缺页且地址位于摘权集合 =>
 *           在 PG 例程入口写入 0xC3 硬编码 + 重定向 RIP 到 ret 存根, 检测逻辑不再执行
 */
BOOLEAN BarricadeArm(VOID);

/**
 * @brief 撤销 Barricade: 还原 MmAccessFault 原始指令、释放跳板、
 *        清除已摘权页面的 NX 位并刷 TLB
 */
VOID BarricadeDisarm(VOID);

#ifdef __cplusplus
}
#endif
