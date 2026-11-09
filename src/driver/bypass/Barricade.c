#include <ntifs.h>
#include <intrin.h>
#include "Bypass.h"
#include "KernelState.h"
#include "Report.h"

#pragma intrinsic(_ReturnAddress)

// =============================================================================
// Barricade 通杀 —— 针对 Pool 与 Independent 页面的定向扫描与缺页拦截防护
//
// 逻辑对照:
//   Hook::HookTrampoline      -> BarricadeHookTrampoline (网关 = 序言拷贝 + jmp[rip] 回跳)
//   HkMmAccessFault           -> BarricadeHkMmAccessFault (_ReturnAddress 校验 + fault 位过滤)
//   CustomNxFaultHandler      -> BarricadeCustomNxFaultHandler (三签名 + 线程重定向 + 自愈)
//   HaltNxFault / HaltNxFault2-> 同名移植 (ret 弹栈 / 线程重定向 KeDelayExecutionThread)
//   FlipPteNxBit              -> 定向针对 PoolBigPageTable 与 SystemPtes (Independent Pages) 翻转 NX
//   ToIgnoreIpxe              -> self-map 索引排除
//   Util/Memory PTE 助手      -> BarricadeGetPteAtLevel / BarricadeGetLastPteLeaf
//   WriteOnReadOnlyMemory     -> KernelHelperWriteReadOnlyMemory (等价 MDL 实现)
//
// 扫描策略优化:
//   - 针对 Pool 内存: 遍历 nt!PoolBigPageTable，直接锁定大页未背书池分配 (如 PG Context 0x62000 字节)
//   - 针对 Independent 内存: 遍历 nt!MiState.SystemPtes，直接锁定 MmAllocateIndependentPages 分配页
//   - 静态/初始化布防: 在 Arm 时刻定向翻转未背书 RWX 页面，消除常驻后台线程开销与锁竞争
// =============================================================================

#define PG_BARRICADE_TAG 'raBP'

// KTRAP_FRAME 字段偏移 (Win10/11 x64, IDA _KTRAP_FRAME 布局实测)
#define KTF_RIP(tf)    (*(PULONG64)((PUCHAR)(tf) + 0x168))
#define KTF_RSP(tf)    (*(PULONG64)((PUCHAR)(tf) + 0x180))
#define KTF_RCX(tf)    (*(PULONG64)((PUCHAR)(tf) + 0x38))
#define KTF_RDX(tf)    (*(PULONG64)((PUCHAR)(tf) + 0x40))
#define KTF_R8(tf)     (*(PULONG64)((PUCHAR)(tf) + 0x48))
#define KTF_EFLAGS(tf) (*(PULONG)((PUCHAR)(tf) + 0x178))

#define BARRICADE_FLUSH_TLB() __writecr3(__readcr3())

#define PG_BARRICADE_HEXDUMP_BYTES 30
#define PG_BARRICADE_SAMPLE_MAX 3      // 未背书区间样本打印上限
#define PG_BARRICADE_RESTORE_LOG_MAX 20

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

// 未文档化导出
NTKERNELAPI VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);
NTKERNELAPI VOID KeSignalCallDpcDone(_In_ PVOID SystemArgument1);
NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

// -----------------------------------------------------------------------------
// 运行时变量
// -----------------------------------------------------------------------------
static PVOID g_MmAccessFaultPtr = NULL;   // nt!MmAccessFault 入口
static PVOID g_FaultingAddrPtr = NULL;    // KiPageFault 中 call 之后的返回地址
static PUCHAR g_TrampolineGateway = NULL; // 网关 (序言拷贝 + 回跳)
static ULONG g_PrologueLength = 0;        // 搬迁序言长度 (运行时解码)
static BOOLEAN g_Hooked = FALSE;
static BOOLEAN g_Armed = FALSE;

static NTSTATUS (NTAPI *g_OrigMmAccessFault)(ULONG_PTR, PVOID, KPROCESSOR_MODE, PVOID) = NULL;

static ULONG g_InterceptCount = 0;    // 签名命中拦截次数
static ULONG g_ThreadSleepCount = 0;  // 线程型实体处置次数
static ULONG g_RestoreCount = 0;      // 误伤自愈次数
static ULONG g_FlipCount = 0;         // 累计翻转页数
static ULONG g_FlipPoolCount = 0;     // 大页池翻转页数
static ULONG g_FlipSystemPteCount = 0;// 独立页面翻转页数
static ULONG g_ProtectedSkips = 0;    // 自镜像/网关跳过页数

// 回滚记录 (卸载精确还原)
typedef struct _PG_FLIPPED_ENTRY {
    PULONG_PTR Entry;   // 页表项指针 (自映射视图内)
    ULONG_PTR Original; // 翻转前原始值
    ULONG_PTR Va;       // 对应虚拟地址 (回滚时刷 TLB)
} PG_FLIPPED_ENTRY;
static PG_FLIPPED_ENTRY *g_Flipped = NULL;
static ULONG g_FlippedCount = 0;
static ULONG g_FlippedCapacity = 0;
static ULONG g_FlipRecordDrops = 0;
static KSPIN_LOCK g_FlipLock;


static ULONG BarricadePrologueBytes(_In_ const UCHAR* Function)
{
    ULONG total = 0;
    while (total < 14 && total < 32) { // 网关回跳需要 >= 14 字节 (jmp[rip]+8)
        ULONG instLen = KernelHelperDecodeInstructionLength(Function + total);
        if (instLen == 0) {
            return 0;
        }
        total += instLen;
    }
    return total;
}

// -----------------------------------------------------------------------------
// 安全读取 + 拦截现场取证
// -----------------------------------------------------------------------------
static BOOLEAN BarricadeReadCodeBytes(_In_ ULONG_PTR Va, _Out_ UCHAR *Buf, _In_ ULONG Len)
{
    ULONG i;
    __try {
        for (i = 0; i < Len; i++) {
            if (!MmIsAddressValid((PVOID)(Va + i))) {
                return FALSE;
            }
            Buf[i] = *(PUCHAR)(Va + i);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static VOID BarricadePrintCodeBytes(_In_ ULONG_PTR Va)
{
    UCHAR code[PG_BARRICADE_HEXDUMP_BYTES];
    ULONG available = PAGE_SIZE - (ULONG)(Va & (PAGE_SIZE - 1));

    RtlZeroMemory(code, sizeof(code));
    if (!BarricadeReadCodeBytes(Va, code, sizeof(code))) {
        if (available > sizeof(code)) {
            available = sizeof(code);
        }
        if (available != 0 && !BarricadeReadCodeBytes(Va, code, available)) {
            PgPrint("[Barricade]   -> 入口前 30 字节: (读取失败)\n");
            return;
        }
    }
    PgPrint("[Barricade]   -> 入口前 30 字节编码: "
        "%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X "
        "%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X "
        "%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
        code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7], code[8], code[9],
        code[10], code[11], code[12], code[13], code[14], code[15], code[16], code[17], code[18], code[19],
        code[20], code[21], code[22], code[23], code[24], code[25], code[26], code[27], code[28], code[29]);
}

// -----------------------------------------------------------------------------
// 自镜像识别 (PE 头校验; kdmapper 等无背书映射必备)
// -----------------------------------------------------------------------------
static PVOID g_SelfImageBase = NULL;
static ULONG g_SelfImageSize = 0;

static BOOLEAN BarricadePeHeaderLooksValid(
    _In_ ULONG_PTR Base, _In_ ULONG_PTR AnchorVa, _Out_ PULONG OutImageSize)
{
    if ((Base & (PAGE_SIZE - 1)) != 0) {
        return FALSE;
    }
    __try {
        if (*(PUSHORT)Base != 0x5A4D) { // 'MZ'
            return FALSE;
        }
        LONG eLfanew = *(PLONG)(Base + 0x3C);
        if (eLfanew <= 0 || eLfanew > 0x1000) {
            return FALSE;
        }
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(Base + eLfanew);
        if (nt->Signature != 0x00004550) { // 'PE\0\0'
            return FALSE;
        }
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return FALSE;
        }
        if (nt->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_NATIVE) {
            return FALSE;
        }
        ULONG imgSize = nt->OptionalHeader.SizeOfImage;
        if (imgSize < PAGE_SIZE || imgSize > 0x4000000) { // 4KB .. 64MB
            return FALSE;
        }
        if (AnchorVa < Base || AnchorVa - Base >= imgSize) {
            return FALSE;
        }
        *OutImageSize = imgSize;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

VOID BarricadeMarkSelfImage(_In_opt_ PDRIVER_OBJECT DriverObject)
{
    if (g_SelfImageBase != NULL) {
        return;
    }
    ULONG imgSize = 0;

    if (DriverObject != NULL && DriverObject->DriverStart != NULL) {
        ULONG_PTR base = (ULONG_PTR)DriverObject->DriverStart;
        if (BarricadePeHeaderLooksValid(base, (ULONG_PTR)&BarricadeMarkSelfImage, &imgSize)) {
            g_SelfImageBase = (PVOID)base;
            g_SelfImageSize = imgSize;
        }
    }

    if (g_SelfImageBase == NULL) {
        ULONG_PTR page = (ULONG_PTR)&BarricadeMarkSelfImage & ~(ULONG_PTR)(PAGE_SIZE - 1);
        for (ULONG i = 0; i < 0x1000 && g_SelfImageBase == NULL; i++, page -= PAGE_SIZE) {
            if (BarricadePeHeaderLooksValid(page, (ULONG_PTR)&BarricadeMarkSelfImage, &imgSize)) {
                g_SelfImageBase = (PVOID)page;
                g_SelfImageSize = imgSize;
            }
        }
    }

    if (g_SelfImageBase != NULL) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[Barricade] 自镜像识别: base=%p size=%lX (摘权将排除本驱动自身)\n",
            g_SelfImageBase, (ULONG_PTR)g_SelfImageSize));
    } else {
        PgPrintErr(
            "[Barricade] 自镜像识别失败 —— 布防将拒绝执行 (否则自身代码页可能被摘权引发取指缺页风暴)\n");
    }
}

static BOOLEAN BarricadeIsCollapsing(
    _In_ ULONG_PTR v1Start, _In_ ULONG_PTR v1End, _In_ ULONG_PTR v2Start, _In_ ULONG_PTR v2End)
{
    return v1End >= v2Start && v2End >= v1Start;
}

static BOOLEAN BarricadeSelfImageCollapsing(_In_ ULONG_PTR Va, _In_ SIZE_T PageSize)
{
    if (g_SelfImageBase == NULL) {
        return FALSE;
    }
    return BarricadeIsCollapsing(Va, Va + PageSize - 1,
        (ULONG_PTR)g_SelfImageBase, (ULONG_PTR)g_SelfImageBase + g_SelfImageSize - 1);
}

// -----------------------------------------------------------------------------
// 回滚记录 (卸载精确还原, 线程安全)
// -----------------------------------------------------------------------------
static VOID BarricadeRecordFlip(_In_ PULONG_PTR Entry, _In_ ULONG_PTR Original, _In_ ULONG_PTR Va)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_FlipLock, &oldIrql);

    if (g_FlippedCount == g_FlippedCapacity) {
        ULONG newCapacity = g_FlippedCapacity ? g_FlippedCapacity * 2 : 256;
#pragma warning(suppress: 4996)
        PG_FLIPPED_ENTRY *grown = (PG_FLIPPED_ENTRY *)ExAllocatePoolWithTag(
            NonPagedPool, newCapacity * sizeof(PG_FLIPPED_ENTRY), PG_BARRICADE_TAG);
        if (grown == NULL) {
            g_FlipRecordDrops++;
            KeReleaseSpinLock(&g_FlipLock, oldIrql);
            return;
        }
        if (g_Flipped != NULL) {
            RtlCopyMemory(grown, g_Flipped, g_FlippedCount * sizeof(PG_FLIPPED_ENTRY));
            ExFreePoolWithTag(g_Flipped, PG_BARRICADE_TAG);
        }
        g_Flipped = grown;
        g_FlippedCapacity = newCapacity;
    }
    g_Flipped[g_FlippedCount].Entry = Entry;
    g_Flipped[g_FlippedCount].Original = Original;
    g_Flipped[g_FlippedCount].Va = Va;
    g_FlippedCount++;

    KeReleaseSpinLock(&g_FlipLock, oldIrql);
}

// -----------------------------------------------------------------------------
// 分层页表项定位
// -----------------------------------------------------------------------------
static UINT64 *BarricadeGetPteAtLevel(_In_ PVOID v, _In_ ULONG level)
{
    switch (level) {
    case 1:
        return (UINT64 *)(g_MmPteBase + (((ULONG_PTR)v >> 9) & 0x7FFFFFFFF8ULL));
    case 2:
        return (UINT64 *)(g_MmPdeBase + (((ULONG_PTR)v >> 18) & 0x3FFFFFF8ULL));
    case 3:
        return (UINT64 *)(g_MmPdpteBase + (((ULONG_PTR)v >> 27) & 0x1FFFF8ULL));
    case 4:
        return (UINT64 *)g_MmPml4eBase + (((ULONG_PTR)v >> 39) & 0x1FF);
    default:
        return NULL;
    }
}

static UINT64 *BarricadeGetLastPteLeaf(_In_ PVOID v)
{
    UINT64 *pml4e = BarricadeGetPteAtLevel(v, 4);
    if (pml4e == NULL || !(*pml4e & 1)) {
        return NULL;
    }
    UINT64 *pdpte = BarricadeGetPteAtLevel(v, 3);
    if (!(*pdpte & 1)) {
        return NULL;
    }
    if ((*pdpte >> 7) & 1) {
        return pdpte; // 1GB 大页叶子
    }
    UINT64 *pde = BarricadeGetPteAtLevel(v, 2);
    if (!(*pde & 1)) {
        return NULL;
    }
    if ((*pde >> 7) & 1) {
        return pde; // 2MB 大页叶子
    }
    UINT64 *pte = BarricadeGetPteAtLevel(v, 1);
    if (!(*pte & 1)) {
        return NULL;
    }
    return pte;
}

static BOOLEAN BarricadeIsValidAddress(_In_ PVOID address)
{
    if (!KernelHelperIsCanonicalAddress(address)) {
        return FALSE;
    }
    return BarricadeGetLastPteLeaf(address) != NULL;
}

static BOOLEAN BarricadeToIgnoreIpxe(_In_ ULONG_PTR ipxeIndex)
{
    if (g_MmPteBase >= 0xFFFF000000000000ULL && ipxeIndex == ((g_MmPteBase >> 39) & 0x1FF)) {
        return TRUE;
    }
    return FALSE;
}

// -----------------------------------------------------------------------------
// 缺页现场处置
// -----------------------------------------------------------------------------
static VOID BarricadeHaltNxFault(_In_ PVOID TrapFrame)
{
    KTF_RIP(TrapFrame) = *(PULONG64)(ULONG_PTR)KTF_RSP(TrapFrame);
    KTF_RSP(TrapFrame) += 8;
}

static VOID BarricadeHaltNxFault2(_In_ PVOID TrapFrame)
{
    KTF_RSP(TrapFrame) &= ~0xFULL;

    KTF_RCX(TrapFrame) = (ULONG64)KernelMode;
    KTF_RDX(TrapFrame) = 0;
    KTF_R8(TrapFrame) = KTF_RSP(TrapFrame) + 0x28;
    *(PULONG64)(ULONG_PTR)KTF_R8(TrapFrame) = (ULONG64)0xFFFFEDCBA9876000ULL;

    *(PULONG64)(ULONG_PTR)KTF_RSP(TrapFrame) = KTF_RIP(TrapFrame);
    KTF_RSP(TrapFrame) += 8;
    KTF_RIP(TrapFrame) = (ULONG64)KeDelayExecutionThread;

    KeLowerIrql(APC_LEVEL);
    KTF_EFLAGS(TrapFrame) |= (1 << 9);
}

static BOOLEAN BarricadeCustomNxFaultHandler(_In_ PVOID faultAddress, _In_ PVOID TrapFrame)
{
    ULONG_PTR pml4Index = ((ULONG_PTR)faultAddress >> 39) & 0x1FF;

    if (pml4Index < 256 || BarricadeToIgnoreIpxe(pml4Index)) {
        return FALSE;
    }

    ULONG_PTR stackPtr = KTF_RSP(TrapFrame) & ~7ULL;
    KIRQL curIrql = KeGetCurrentIrql();

    UINT64 *pte = BarricadeGetLastPteLeaf(faultAddress);
    if (pte == NULL) {
        return FALSE;
    }
    if ((*pte >> 2) & 1) { // U/S=1 用户页: 不处理
        return FALSE;
    }

    UCHAR instBytes[0x40] = { 0 };
    BOOLEAN haveInst = FALSE;

    if (curIrql >= DISPATCH_LEVEL) {
        haveInst = BarricadeReadCodeBytes(KTF_RIP(TrapFrame), instBytes, sizeof(instBytes));
    }

    if (curIrql >= DISPATCH_LEVEL && haveInst) {
        // CmpAppendDllSection
        if (instBytes[0] == 0x2E && instBytes[1] == 0x48 && instBytes[2] == 0x31 &&
            !KernelHelperIsCanonicalAddress((PVOID)KTF_RDX(TrapFrame)) &&
            KTF_RCX(TrapFrame) == KTF_RIP(TrapFrame)) {
            g_InterceptCount++;
            PgPrint("[Barricade] 拦截 CmpAppendDllSection 型 PG 调用 (%p), 页面保持 NX (累计 %lu 次)\n",
                (PVOID)KTF_RIP(TrapFrame), g_InterceptCount);
            BarricadePrintCodeBytes(KTF_RIP(TrapFrame));
            BarricadeHaltNxFault(TrapFrame);
            return TRUE;
        }

        // KiDpcDispatch
        if (instBytes[0] == 0x48 && instBytes[1] == 0x31 &&
            !KernelHelperIsCanonicalAddress((PVOID)KTF_RDX(TrapFrame)) &&
            KTF_RIP(TrapFrame) - 0x60 < KTF_RCX(TrapFrame) &&
            KTF_RIP(TrapFrame) + 0x60 > KTF_RCX(TrapFrame)) {
            g_InterceptCount++;
            PgPrint("[Barricade] 拦截 KiDpcDispatch 型 PG 调用 (%p), 页面保持 NX (累计 %lu 次)\n",
                (PVOID)KTF_RIP(TrapFrame), g_InterceptCount);
            BarricadePrintCodeBytes(KTF_RIP(TrapFrame));
            BarricadeHaltNxFault(TrapFrame);
            return TRUE;
        }

        // KiTimerDispatch
        for (ULONG i = 0; i < 0x20; i++) {
            if (instBytes[i] == 0x48 && instBytes[i + 1] == 0x9C) {
                for (ULONG j = i; j < i + 0x20 && j + 1 < sizeof(instBytes); j++) {
                    if (instBytes[j] == 0x48 && instBytes[j + 1] == 0x83) {
                        g_InterceptCount++;
                        PgPrint("[Barricade] 拦截 KiTimerDispatch 型 PG 调用 (%p), 页面保持 NX (累计 %lu 次)\n",
                            (PVOID)KTF_RIP(TrapFrame), g_InterceptCount);
                        BarricadePrintCodeBytes(KTF_RIP(TrapFrame));
                        BarricadeHaltNxFault(TrapFrame);
                        return TRUE;
                    }
                }
            }
        }

        if (curIrql > DISPATCH_LEVEL) {
            goto FalsePositive;
        }
        if (PsGetCurrentProcess() != PsInitialSystemProcess) {
            goto FalsePositive;
        }
        if (KeIsExecutingDpc()) {
            goto FalsePositive;
        }
    }

    // 线程型 (M3/M4) 处置
    {
        ULONG_PTR lastValidVp = 0;
        for (ULONG step = 0; step < 0x20; step++) {
            ULONG_PTR valuePtr = stackPtr + step * sizeof(PVOID);
            ULONG_PTR vp = valuePtr >> 12;
            if (vp != lastValidVp) {
                if (!BarricadeIsValidAddress((PVOID)valuePtr)) {
                    break;
                }
                lastValidVp = vp;
            }

            ULONG_PTR value = *(PULONG_PTR)valuePtr;
            if (value == (ULONG_PTR)KeDelayExecutionThread ||
                value == (ULONG_PTR)KeWaitForMultipleObjects ||
                value == (ULONG_PTR)KeWaitForSingleObject) {
                g_ThreadSleepCount++;
                PgPrint("[Barricade] 拦截线程型 PG 执行实体 (%p) => 已重定向 KeDelayExecutionThread 长超时 (累计 %lu 次)\n",
                    faultAddress, g_ThreadSleepCount);
                BarricadePrintCodeBytes((ULONG_PTR)faultAddress);
                BarricadeHaltNxFault2(TrapFrame);
                return TRUE;
            }
        }
    }

FalsePositive:
    g_RestoreCount++;
    if (g_RestoreCount <= PG_BARRICADE_RESTORE_LOG_MAX) {
        PgPrint("[Barricade] 误伤自愈: %p 未命中 PG 形态, 已恢复执行权 (累计 %lu 次)\n",
            faultAddress, g_RestoreCount);
        BarricadePrintCodeBytes((ULONG_PTR)faultAddress);
    }
    *pte &= ~(1ULL << 63);
    BARRICADE_FLUSH_TLB();
    return FALSE;
}

static NTSTATUS NTAPI BarricadeHkMmAccessFault(
    _In_ ULONG_PTR FaultCode,
    _In_ PVOID Address,
    _In_ KPROCESSOR_MODE Mode,
    _In_ PVOID TrapInformation)
{
    if (_ReturnAddress() == g_FaultingAddrPtr) {
        if (!((FaultCode >> 2) & 1) && !((FaultCode >> 1) & 1) && TrapInformation != NULL) {
            if (BarricadeCustomNxFaultHandler(Address, TrapInformation)) {
                return STATUS_SUCCESS;
            }
        }
    }

    return g_OrigMmAccessFault(FaultCode, Address, Mode, TrapInformation);
}

// -----------------------------------------------------------------------------
// 检测阶段聚合辅助结构与函数
// -----------------------------------------------------------------------------
typedef struct _PG_DETECT_WALK {
    ULONG_PTR Start;
    ULONG_PTR End;
    BOOLEAN HasModule;
    UNICODE_STRING ModuleName;
    ULONG ReportCount;
    ULONG Regions;
    ULONG Unbacked;
    ULONG Module;
    BOOLEAN ReportToPg;
} PG_DETECT_WALK;

static VOID BarricadeDetectFlush(_Inout_ PG_DETECT_WALK *Walk)
{
    UCHAR hexBytes[16] = { 0 };
    BOOLEAN canRead = FALSE;

    if (Walk->Start == 0) {
        return;
    }
    Walk->Regions++;
    if (Walk->HasModule) {
        Walk->Module++;
    } else {
        Walk->Unbacked++;
    }
    if (Walk->ReportToPg) {
        PgReportFoundRwxRange((PVOID)Walk->Start, (PVOID)Walk->End);
    }

    if (Walk->ReportToPg && !Walk->HasModule && Walk->ReportCount < PG_BARRICADE_SAMPLE_MAX) {
        Walk->ReportCount++;
        __try {
            if (MmIsAddressValid((PVOID)Walk->Start)) {
                RtlCopyMemory(hexBytes, (PVOID)Walk->Start, sizeof(hexBytes));
                canRead = TRUE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            canRead = FALSE;
        }
        if (PgReportConfig() && PgReportConfig()->LogLevel) {
            PgPrint("未归属模块 RWX 区间样本 #%lu [%p, %p]\n",
                Walk->ReportCount, (PVOID)Walk->Start, (PVOID)Walk->End);
            if (canRead) {
                PgPrint(
                    "           -> 块首 16 字节: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
                    hexBytes[0], hexBytes[1], hexBytes[2], hexBytes[3],
                    hexBytes[4], hexBytes[5], hexBytes[6], hexBytes[7],
                    hexBytes[8], hexBytes[9], hexBytes[10], hexBytes[11],
                    hexBytes[12], hexBytes[13], hexBytes[14], hexBytes[15]);
            }
        }
    }
    Walk->Start = 0;
    Walk->End = 0;
}

static VOID BarricadeDetectAddLeaf(
    _Inout_ PG_DETECT_WALK *Walk, _In_ ULONG_PTR Va, _In_ SIZE_T PageSize)
{
    UNICODE_STRING modName = { 0 };
    ULONG_PTR offset = 0;
    BOOLEAN hasMod;
    BOOLEAN merged = FALSE;

    if (BarricadeSelfImageCollapsing(Va, PageSize)) {
        return;
    }
    if (g_TrampolineGateway != NULL &&
        BarricadeIsCollapsing(Va, Va + PageSize - 1,
            (ULONG_PTR)g_TrampolineGateway, (ULONG_PTR)g_TrampolineGateway + PAGE_SIZE - 1)) {
        return;
    }

    hasMod = KernelHelperFindModuleByAddress((PVOID)Va, &modName, &offset);

    if (Walk->Start != 0) {
        BOOLEAN contiguous = (Va == Walk->End + 1);
        BOOLEAN sameModule = (hasMod == Walk->HasModule) &&
            (!hasMod || modName.Buffer == Walk->ModuleName.Buffer);
        if (contiguous && sameModule) {
            Walk->End = Va + (PageSize - 1);
            merged = TRUE;
        } else {
            BarricadeDetectFlush(Walk);
        }
    }
    if (!merged) {
        Walk->Start = Va;
        Walk->End = Va + (PageSize - 1);
        Walk->HasModule = hasMod;
        Walk->ModuleName = modName;
    }
}

// -----------------------------------------------------------------------------
// 1. 定向扫描 PoolBigPageTable (大页池内存)
// -----------------------------------------------------------------------------
static VOID BarricadeScanPoolBigPages(_In_ BOOLEAN ArmNx, _Inout_opt_ PG_DETECT_WALK *Walk)
{
    if (g_PoolBigPageTableVar == NULL || g_PoolBigPageTableSizeVar == NULL) {
        return;
    }
    if (!MmIsAddressValid(g_PoolBigPageTableVar) || !MmIsAddressValid(g_PoolBigPageTableSizeVar)) {
        return;
    }

    // 动态解引用获取当前最新的表指针与容量
    // 注意: Windows 内核会在 Big Pool 扩容时重新分配更大的数组，并将旧表释放为未映射物理页，必须每次动态读取
    PPOOL_TRACKER_BIG_PAGES table = *g_PoolBigPageTableVar;
    ULONG size = *g_PoolBigPageTableSizeVar;

    if (table == NULL || size == 0) {
        return;
    }

    for (ULONG i = 0; i < size; i++) {
        POOL_TRACKER_BIG_PAGES entry;

        // 安全读取表项，杜绝在系统并发重分配或释放内存时触发 0x50 缺页 BugCheck
        if (!MmIsAddressValid(&table[i])) {
            break;
        }
        __try {
            entry = table[i];
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }

        ULONG_PTR rawVa = entry.Va;
        // 最低位为 1 表示未分配/已释放
        if (rawVa == 0 || (rawVa & 1) != 0) {
            continue;
        }

        ULONG_PTR va = rawVa & ~1ULL;
        ULONG_PTR numBytes = entry.NumberOfBytes;

        if (!KernelHelperIsCanonicalAddress((PVOID)va) || numBytes == 0) {
            continue;
        }

        // 驱动模块背书检查: 过滤合法驱动的大页映射
        UNICODE_STRING modName = { 0 };
        ULONG_PTR modOffset = 0;
        if (KernelHelperFindModuleByAddress((PVOID)va, &modName, &modOffset)) {
            continue;
        }

        for (ULONG_PTR pageVa = va; pageVa < va + numBytes; pageVa += PAGE_SIZE) {
            UINT64 *ptEntryPtr = BarricadeGetLastPteLeaf((PVOID)pageVa);
            if (ptEntryPtr == NULL) {
                continue;
            }

            UINT64 pteVal = 0;
            if (!MmIsAddressValid(ptEntryPtr)) {
                continue;
            }
            __try {
                pteVal = *ptEntryPtr;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }

            if (!(pteVal & 1)) {
                continue;
            }

            // 检查 Writable 且未 NX
            if (!((pteVal >> 1) & 1) || ((pteVal >> 63) & 1)) {
                continue;
            }

            if (BarricadeSelfImageCollapsing(pageVa, PAGE_SIZE)) {
                g_ProtectedSkips++;
                continue;
            }
            if (g_TrampolineGateway != NULL &&
                BarricadeIsCollapsing(pageVa, pageVa + PAGE_SIZE - 1,
                    (ULONG_PTR)g_TrampolineGateway, (ULONG_PTR)g_TrampolineGateway + PAGE_SIZE - 1)) {
                g_ProtectedSkips++;
                continue;
            }

            if (ArmNx) {
                BarricadeRecordFlip((PULONG_PTR)ptEntryPtr, pteVal, pageVa);
                *ptEntryPtr |= (1ULL << 63);
                g_FlipCount++;
                g_FlipPoolCount++;
            } else if (Walk != NULL) {
                BarricadeDetectAddLeaf(Walk, pageVa, PAGE_SIZE);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// 2. 定向扫描 SystemPtes (Independent Pages 独立页面)
// -----------------------------------------------------------------------------
static VOID BarricadeScanSystemPtes(_In_ BOOLEAN ArmNx, _Inout_opt_ PG_DETECT_WALK *Walk)
{
    if (g_SystemPteBase == 0 || g_TotalSystemPtes == 0 || g_MmPteBase == 0) {
        return;
    }

    PULONG_PTR basePte = (PULONG_PTR)g_SystemPteBase;

    // 按 512 个 PTE (1 个 4KB 页表页 = 2MB 虚存) 分块快速推进
    for (ULONG_PTR i = 0; i < g_TotalSystemPtes; i += 512) {
        PULONG_PTR pteChunk = basePte + i;
        if (!MmIsAddressValid(pteChunk)) {
            continue; // 未分配页表页整块快速跳过
        }

        for (ULONG j = 0; j < 512 && (i + j) < g_TotalSystemPtes; j++) {
            PULONG_PTR pPte = pteChunk + j;
            ULONG_PTR pteVal = 0;
            if (!MmIsAddressValid(pPte)) {
                continue;
            }
            __try {
                pteVal = *pPte;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }

            if (!(pteVal & 1)) {
                continue;
            }

            // Writable 且未 NX
            if (!((pteVal >> 1) & 1) || ((pteVal >> 63) & 1)) {
                continue;
            }

            // 计算该 PTE 对应的虚拟地址
            ULONG_PTR curPteAddr = (ULONG_PTR)pPte;
            ULONG_PTR pageVa = (curPteAddr - g_MmPteBase) << 9;
            if ((pageVa >> 47) & 1) {
                pageVa |= 0xFFFF000000000000ULL;
            }

            if (BarricadeSelfImageCollapsing(pageVa, PAGE_SIZE)) {
                g_ProtectedSkips++;
                continue;
            }
            if (g_TrampolineGateway != NULL &&
                BarricadeIsCollapsing(pageVa, pageVa + PAGE_SIZE - 1,
                    (ULONG_PTR)g_TrampolineGateway, (ULONG_PTR)g_TrampolineGateway + PAGE_SIZE - 1)) {
                g_ProtectedSkips++;
                continue;
            }

            UNICODE_STRING modName = { 0 };
            ULONG_PTR modOffset = 0;
            if (KernelHelperFindModuleByAddress((PVOID)pageVa, &modName, &modOffset)) {
                continue;
            }

            if (ArmNx) {
                BarricadeRecordFlip(pPte, pteVal, pageVa);
                *pPte |= (1ULL << 63);
                g_FlipCount++;
                g_FlipSystemPteCount++;
            } else if (Walk != NULL) {
                BarricadeDetectAddLeaf(Walk, pageVa, PAGE_SIZE);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// 全核 TLB 广播刷新存根
// -----------------------------------------------------------------------------
static BOOLEAN NTAPI BarricadeBroadcastFlushTlb(
    _In_ KDPC *Dpc, _In_opt_ PVOID DeferredContext, _In_ PVOID SystemArgument1, _In_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    BARRICADE_FLUSH_TLB();
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
    return TRUE;
}

// -----------------------------------------------------------------------------
// 兜底全量递归扫描 (当针对性结构未能动态解析时备用)
// -----------------------------------------------------------------------------
static VOID BarricadeRecurseFlip(_In_ PVOID virtualAddress, _In_ ULONG remainingRecurse)
{
    UINT64 *ptEntryPtr = BarricadeGetPteAtLevel(virtualAddress, remainingRecurse);
    if (ptEntryPtr == NULL || !(*ptEntryPtr & 1)) {
        return;
    }

    if (remainingRecurse > 1) {
        if (!((*ptEntryPtr >> 7) & 0x1)) {
            for (ULONG ipte = 0; ipte < 512; ipte++) {
                BarricadeRecurseFlip(
                    (PVOID)((ULONG_PTR)virtualAddress | ((ULONG_PTR)ipte << (12 + 9 * (remainingRecurse - 2)))),
                    remainingRecurse - 1);
            }
            return;
        }
    }

    if (!((*ptEntryPtr >> 1) & 0x1) || ((*ptEntryPtr >> 63) & 0x1)) {
        return;
    }

    SIZE_T pageSize = 1ULL << (12 + 9 * (remainingRecurse - 1));

    if (BarricadeSelfImageCollapsing((ULONG_PTR)virtualAddress, pageSize)) {
        g_ProtectedSkips++;
        return;
    }

    if (g_TrampolineGateway != NULL &&
        BarricadeIsCollapsing((ULONG_PTR)virtualAddress, (ULONG_PTR)virtualAddress + pageSize - 1,
            (ULONG_PTR)g_TrampolineGateway, (ULONG_PTR)g_TrampolineGateway + PAGE_SIZE - 1)) {
        g_ProtectedSkips++;
        return;
    }

    BarricadeRecordFlip((PULONG_PTR)ptEntryPtr, *ptEntryPtr, (ULONG_PTR)virtualAddress);
    g_FlipCount++;
    *ptEntryPtr |= (1ULL << 63);
}

static BOOLEAN NTAPI BarricadeFlipPteNxBitIdPc(
    _In_ KDPC *Dpc, _In_opt_ PVOID DeferredContext, _In_ PVOID SystemArgument1, _In_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    ULONG procTotal = KeQueryActiveProcessorCountEx(0);
    ULONG procNum = KeGetCurrentProcessorNumberEx(NULL);

    ULONG rangePerCpu = max(256 / procTotal, 1);
    ULONG rangeStart = min(256 + procNum * rangePerCpu, 512);
    ULONG rangeEnd = min(256 + (procNum + 1) * rangePerCpu, 512);
    if (procNum == procTotal - 1) {
        rangeEnd = 512;
    }

    for (ULONG ipxe = rangeStart; ipxe < rangeEnd; ipxe++) {
        if (BarricadeToIgnoreIpxe(ipxe)) {
            continue;
        }
        ULONG_PTR trimmed = ((ULONG_PTR)ipxe << 39);
        if ((trimmed >> 47) & 1) {
            trimmed |= 0xFFFF000000000000ULL;
        }
        BarricadeRecurseFlip((PVOID)trimmed, 4);
    }

    BARRICADE_FLUSH_TLB();

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
    return TRUE;
}

static VOID BarricadeFlipPteNxBit(VOID)
{
    ULONG before = g_FlipCount;
    BOOLEAN targeted = FALSE;

    if (g_PoolBigPageTableVar != NULL && g_PoolBigPageTableSizeVar != NULL) {
        BarricadeScanPoolBigPages(TRUE, NULL);
        targeted = TRUE;
    }

    if (g_SystemPteBase != 0 && g_TotalSystemPtes > 0) {
        BarricadeScanSystemPtes(TRUE, NULL);
        targeted = TRUE;
    }

    if (targeted) {
        KeGenericCallDpc((PKDEFERRED_ROUTINE)BarricadeBroadcastFlushTlb, NULL);
    } else {
        // 兜底回退按 CPU 分片递归
        KeGenericCallDpc((PKDEFERRED_ROUTINE)BarricadeFlipPteNxBitIdPc, NULL);
    }

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[Barricade] FlipPteNxBit: 完成 (本次新增翻转 %lu 页, 累计 %lu 页)\n",
        g_FlipCount - before, g_FlipCount));
}

// -----------------------------------------------------------------------------
// Hook 网关安装
// -----------------------------------------------------------------------------
static BOOLEAN BarricadeHookTrampoline(
    _In_ PVOID origFunction,
    _In_ PVOID hookFunction,
    _In_ PVOID gateway,
    _In_ SIZE_T len)
{
    UCHAR detourTemplate[] = { 0xFF, 0x25, 0, 0, 0, 0 }; // jmp qword ptr [rip+0]
    ULONG_PTR returnAddress;
    ULONG_PTR detourAddress;
    UCHAR patchBuffer[32];

    if (origFunction == NULL || hookFunction == NULL || gateway == NULL) {
        return FALSE;
    }

    if (len < sizeof(detourTemplate) + sizeof(ULONG_PTR) || len > sizeof(patchBuffer)) {
        return FALSE;
    }

    // 1. 网关前部: 拷贝原始序言指令 (origFunction -> gateway)
    // gateway 是由 ExAllocatePoolWithTag(NonPagedPoolExecute, ...) 分配的可写内存
    RtlCopyMemory(gateway, origFunction, len);

    // 2. 网关后部: 写入回跳指令 jmp [rip+0] + 原始续接地址
    returnAddress = (ULONG_PTR)origFunction + len;
    RtlCopyMemory((PUCHAR)gateway + len, detourTemplate, sizeof(detourTemplate));
    RtlCopyMemory((PUCHAR)gateway + len + sizeof(detourTemplate), &returnAddress, sizeof(returnAddress));

    // 3. 构造原函数入口的补丁 (一次性原子替换整个序言，多余字节填充 NOP，避免并发缺页竞争)
    // 补丁格式: jmp [rip+0] (6 字节) + hookFunction 地址 (8 字节) + NOP (0x90) 填充多余字节
    RtlFillMemory(patchBuffer, len, 0x90);
    RtlCopyMemory(patchBuffer, detourTemplate, sizeof(detourTemplate));
    detourAddress = (ULONG_PTR)hookFunction;
    RtlCopyMemory(patchBuffer + sizeof(detourTemplate), &detourAddress, sizeof(detourAddress));

    // 4. 将补丁写入只读代码段 (nt!MmAccessFault)
    // KernelHelperWriteReadOnlyMemory(Destination, Source, Length)
    if (!KernelHelperWriteReadOnlyMemory(origFunction, patchBuffer, len)) {
        return FALSE;
    }

    return TRUE;
}

// -----------------------------------------------------------------------------
// 特征定位 (19041 验证)
// -----------------------------------------------------------------------------
static const UCHAR PgMmAccessFaultPat[] = {
    0x4C, 0x8B, 0xDC, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x56,
    0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x33, 0xC4
};
// 序言 27 字节: 13 字节固定前缀 + 4 字节栈帧偏移 + 3 字节 mov rax,cs:cookie + 4 字节 disp32 + 3 字节 xor rax,rsp
static const char PgMmAccessFaultMask[] = "xxxxxxxxxxxxx????xxx????xxx";
C_ASSERT(sizeof(PgMmAccessFaultMask) - 1 == sizeof(PgMmAccessFaultPat));

static const UCHAR PgFaultingAddrPat[] = { 0x85, 0xC0, 0x7C, 0x36, 0x80, 0x3D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x12 };
static const char PgFaultingAddrMask[] = "xxxxxx????xxx";
C_ASSERT(sizeof(PgFaultingAddrMask) - 1 == sizeof(PgFaultingAddrPat));

static BOOLEAN BarricadeResolveHookTargets(VOID)
{
    ULONG textSectionSize = 0;
    PUCHAR textBase = (PUCHAR)KernelHelperGetSectionAddress(KernelHelperGetKernelBase(NULL), ".text", &textSectionSize);
    PUCHAR match = NULL;

    // 1. nt!MmAccessFault
    if (textBase != NULL && textSectionSize > 0) {
        match = KernelHelperFindPattern(textBase, textSectionSize, PgMmAccessFaultPat, PgMmAccessFaultMask);
    }
    if (match == NULL) {
        ULONG kernelSize = 0;
        PVOID kernelBase = KernelHelperGetKernelBase(&kernelSize);
        if (kernelBase != NULL && kernelSize > 0) {
            match = KernelHelperFindPattern((PUCHAR)kernelBase, kernelSize, PgMmAccessFaultPat, PgMmAccessFaultMask);
        }
    }
    if (match == NULL) {
        PgPrintErr("[Barricade] MmAccessFault 特征未命中, 无法布防\n");
        return FALSE;
    }
    g_MmAccessFaultPtr = match;

    // 2. KiPageFault 中 call MmAccessFault 的返回地址 (_ReturnAddress 校验锚点)
    match = NULL;
    if (textBase != NULL && textSectionSize > 0) {
        match = KernelHelperFindPattern(textBase, textSectionSize, PgFaultingAddrPat, PgFaultingAddrMask);
    }
    if (match == NULL) {
        PgPrintErr("[Barricade] FaultingAddr 特征未命中 (KiPageFault 调用点), 无法布防\n");
        return FALSE;
    }
    g_FaultingAddrPtr = match;

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[Barricade] 定位完成: MmAccessFault=%p, FaultingAddr=%p (kernelBase+%lX)\n",
        g_MmAccessFaultPtr, g_FaultingAddrPtr,
        (ULONG_PTR)((PUCHAR)g_FaultingAddrPtr - (PUCHAR)KernelHelperGetKernelBase(NULL))));
    return TRUE;
}

// -----------------------------------------------------------------------------
// 布防 / 撤防
// -----------------------------------------------------------------------------

BOOLEAN BarricadeArm(VOID)
{
    ULONG_PTR gatewaySize;

    if (g_Armed) {
        return TRUE;
    }

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "\n==================== [Barricade 通杀启动 (定向 Pool/Independent 架构)] ====================\n"));

    // 0. 自镜像必须已识别
    if (g_SelfImageBase == NULL) {
        BarricadeMarkSelfImage(NULL);
        if (g_SelfImageBase == NULL) {
            PgReportAction(PgBarricade, PgActionFailed, "self image unresolved, refuse to arm");
            PgPrintErr("[Barricade] 拒绝布防: 自镜像未识别\n");
            return FALSE;
        }
    }

    // 初始化回滚记录自旋锁
    KeInitializeSpinLock(&g_FlipLock);

    // 1. 特征定位
    if (!BarricadeResolveHookTargets()) {
        PgReportAction(PgBarricade, PgActionFailed, "pattern resolution failed");
        return FALSE;
    }

    // 2. 序言长度解码 + 网关分配
    g_PrologueLength = BarricadePrologueBytes((PUCHAR)g_MmAccessFaultPtr);
    if (g_PrologueLength < 14 || g_PrologueLength > 32) {
        PgReportAction(PgBarricade, PgActionFailed, "prologue relocation failed");
        PgPrintErr("[Barricade] MmAccessFault 序言搬迁长度不可用 (%u)\n", g_PrologueLength);
        return FALSE;
    }
    gatewaySize = (ULONG_PTR)g_PrologueLength + 6 + 8;
#pragma warning(suppress: 4996)
    g_TrampolineGateway = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, gatewaySize, PG_BARRICADE_TAG);
    if (g_TrampolineGateway == NULL) {
        PgReportAction(PgBarricade, PgActionFailed, "gateway allocation failed");
        PgPrintErr("[Barricade] 网关分配失败\n");
        return FALSE;
    }
    RtlZeroMemory(g_TrampolineGateway, gatewaySize);

    // 3. Hook 安装
    if (!BarricadeHookTrampoline(g_MmAccessFaultPtr, BarricadeHkMmAccessFault, g_TrampolineGateway, g_PrologueLength)) {
        PgReportAction(PgBarricade, PgActionFailed, "hook install failed");
        ExFreePoolWithTag(g_TrampolineGateway, PG_BARRICADE_TAG);
        g_TrampolineGateway = NULL;
        return FALSE;
    }
    g_Hooked = TRUE;
    g_OrigMmAccessFault = (NTSTATUS(NTAPI *)(ULONG_PTR, PVOID, KPROCESSOR_MODE, PVOID))g_TrampolineGateway;
    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[Barricade] MmAccessFault hook 安装完成: 入口=%p 网关=%p 序言=%u 字节\n",
        g_MmAccessFaultPtr, g_TrampolineGateway, g_PrologueLength));

    // 4. 定向翻转 RWX 页 (PoolBigPageTable + SystemPtes)
    BarricadeFlipPteNxBit();

    g_Armed = TRUE;
    PgReportAction(PgBarricade, PgActionApplied, "barricade armed (hook + targeted NX flip)");
    PgPrint("[Barricade] 通杀已激活: 共翻转 %lu 个未背书 RWX 页面 (大页池: %lu, 独立页面: %lu), 自镜像跳过 %lu 项 | 缺页拦截已就绪\n",
        g_FlipCount, g_FlipPoolCount, g_FlipSystemPteCount, g_ProtectedSkips);

    return TRUE;
}

VOID BarricadeDisarm(VOID)
{
    if (!g_Armed) {
        return;
    }

    // 1. 精确回滚所有被翻转的页表项
    for (ULONG i = 0; i < g_FlippedCount; i++) {
        PULONG_PTR pEntry = g_Flipped[i].Entry;
        if (pEntry == NULL || !MmIsAddressValid(pEntry)) {
            continue;
        }
        __try {
            ULONG_PTR currentPte = *pEntry;
            // 关键安全校验 1: 若该页在驱动运行期间已被系统释放/解提交 (Present=0)，
            // 严禁复活它，防止踩踏或覆盖内核堆/内存管理器的最新状态
            if (!(currentPte & 1)) {
                continue;
            }
            // 关键安全校验 2: 绝不整字还原陈旧的 Original (避免覆盖系统最新 PFN 与标志位)
            // 仅原子清除第 63 位 (NX 标志)，安全恢复执行权
            InterlockedAnd64((volatile LONG64 *)pEntry, ~(1ULL << 63));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    if (g_FlippedCount != 0) {
        // 关键安全校验 3: 全核广播刷新 TLB，确保所有 CPU 核心同步生效
        KeGenericCallDpc((PKDEFERRED_ROUTINE)BarricadeBroadcastFlushTlb, NULL);
    }
    if (g_FlipRecordDrops != 0) {
        PgPrintErr("[Barricade] 警告: %lu 个页表项无回滚记录 (分配失败), 保持 NX 状态\n", g_FlipRecordDrops);
    }
    PgPrint("[Barricade] 通杀已撤销: %lu 个页表项执行权已恢复 (签名拦截 %lu, 线程处置 %lu, 误伤自愈 %lu)\n",
        g_FlippedCount, g_InterceptCount, g_ThreadSleepCount, g_RestoreCount);

    // 2. 摘除 hook (还原 MmAccessFault 序言)
    if (g_Hooked && g_MmAccessFaultPtr != NULL && g_TrampolineGateway != NULL) {
        if (KernelHelperWriteReadOnlyMemory(g_MmAccessFaultPtr, g_TrampolineGateway, g_PrologueLength)) {
            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[Barricade] MmAccessFault 原始序言已还原 (%u 字节)\n", g_PrologueLength));
        } else {
            PgPrintErr("[Barricade] MmAccessFault 序言还原失败\n");
        }
        g_Hooked = FALSE;
    }
    // 等待在途的 #PF 异常处理彻底退出网关
    LARGE_INTEGER gatewayDrain;
    gatewayDrain.QuadPart = -50 * 10000; // 50ms
    KeDelayExecutionThread(KernelMode, FALSE, &gatewayDrain);

    if (g_TrampolineGateway != NULL) {
        ExFreePoolWithTag(g_TrampolineGateway, PG_BARRICADE_TAG);
        g_TrampolineGateway = NULL;
    }

    // 3. 释放回滚记录与计数
    if (g_Flipped != NULL) {
        ExFreePoolWithTag(g_Flipped, PG_BARRICADE_TAG);
        g_Flipped = NULL;
    }
    g_FlippedCount = 0;
    g_FlippedCapacity = 0;
    g_FlipRecordDrops = 0;
    g_ProtectedSkips = 0;
    g_RestoreCount = 0;
    g_InterceptCount = 0;
    g_ThreadSleepCount = 0;
    g_FlipCount = 0;
    g_FlipPoolCount = 0;
    g_FlipSystemPteCount = 0;
    g_Armed = FALSE;
}


// -----------------------------------------------------------------------------
// 兜底全量检测递归
// -----------------------------------------------------------------------------
static VOID BarricadeDetectRecurse(
    _Inout_ PG_DETECT_WALK *Walk, _In_ PVOID virtualAddress, _In_ ULONG remainingRecurse)
{
    UINT64 *ptEntryPtr = BarricadeGetPteAtLevel(virtualAddress, remainingRecurse);
    if (ptEntryPtr == NULL) {
        return;
    }
    if (!MmIsAddressValid(ptEntryPtr)) {
        if (Walk->ReportToPg) {
            PgReportRwxSkip();
        }
        return;
    }
    if (!(*ptEntryPtr & 1)) {
        return;
    }

    if (remainingRecurse > 1) {
        if (!((*ptEntryPtr >> 7) & 0x1)) {
            for (ULONG ipte = 0; ipte < 512; ipte++) {
                BarricadeDetectRecurse(
                    Walk,
                    (PVOID)((ULONG_PTR)virtualAddress | ((ULONG_PTR)ipte << (12 + 9 * (remainingRecurse - 2)))),
                    remainingRecurse - 1);
            }
            return;
        }
    }

    if (!((*ptEntryPtr >> 1) & 0x1) || ((*ptEntryPtr >> 63) & 0x1)) {
        return; // 仅 RWX
    }

    BarricadeDetectAddLeaf(Walk, (ULONG_PTR)virtualAddress, 1ULL << (12 + 9 * (remainingRecurse - 1)));
}

// -----------------------------------------------------------------------------
// RWX 内存扫描入口 (检测阶段: Pool + Independent 页面针对性扫描)
// -----------------------------------------------------------------------------
ULONG BarricadeScan(VOID)
{
    PG_DETECT_WALK walk;
    RtlZeroMemory(&walk, sizeof(walk));
    walk.ReportToPg = TRUE;

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "\n==================== [RWX 页遍历: 针对 Pool 与 Independent 页面] ====================\n"));

    if (g_MmPteBase == 0 || g_MmPdeBase == 0 || g_MmPdpteBase == 0 || g_MmPml4eBase == 0) {
        PgReportError(PgBarricade, "kernel page table bases unavailable");
        return 0;
    }

    __try {
        BOOLEAN targeted = FALSE;
        if (g_PoolBigPageTableVar != NULL && g_PoolBigPageTableSizeVar != NULL) {
            BarricadeScanPoolBigPages(FALSE, &walk);
            targeted = TRUE;
        }
        if (g_SystemPteBase != 0 && g_TotalSystemPtes > 0) {
            BarricadeScanSystemPtes(FALSE, &walk);
            targeted = TRUE;
        }

        if (!targeted) {
            // 针对性结构未定位时，兜底全量 PML4 递归
            ULONG_PTR selfMapIndex = 0xFFFFFFFFULL;
            if ((ULONG_PTR)g_MmPteBase >= 0xFFFF000000000000ULL) {
                selfMapIndex = ((ULONG_PTR)g_MmPteBase >> 39) & 0x1FF;
            }
            for (ULONG ipxe = 256; ipxe < 512; ipxe++) {
                if ((ULONG_PTR)ipxe == selfMapIndex || BarricadeToIgnoreIpxe(ipxe)) {
                    continue;
                }
                ULONG_PTR trimmed = ((ULONG_PTR)ipxe << 39);
                if ((trimmed >> 47) & 1) {
                    trimmed |= 0xFFFF000000000000ULL;
                }
                BarricadeDetectRecurse(&walk, (PVOID)trimmed, 4);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        PgReportRwxError();
    }

    BarricadeDetectFlush(&walk);
    PgReportRwx(walk.Regions, walk.Unbacked, walk.Module);
    if (PgReportRwxCounts()[5]) {
        if (walk.Regions) PgReportPartial(PgBarricade, "kernel page table traversal interrupted");
        else PgReportError(PgBarricade, "kernel page table traversal interrupted");
    } else if (PgReportRwxCounts()[4]) {
        PgReportPartial(PgBarricade, "unreadable kernel page table entries skipped");
    }

    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[Barricade] RWX 遍历结束: 区间 %lu 个 (未背书 %lu / 模块 %lu)\n",
        walk.Regions, walk.Unbacked, walk.Module));
    return walk.Regions;
}
