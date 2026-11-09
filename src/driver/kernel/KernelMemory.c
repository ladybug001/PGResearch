#include "KernelState.h"

VOID ResolvePteBase(VOID)
{
    if (g_KernelBase == NULL || g_KernelSize == 0) {
        return;
    }

    // 经典 Windows 10/11 KiMarkBugCheckRegions 中获取 MmPteBase 的特征签名：
    //   mov rax, cs:MmPteBase ; 48 8B 05 [disp32]
    //   shr rbx, 9            ; 48 C1 EB 09
    //   lea rcx, [...]        ; 48 8D 4D ...
    const UCHAR ptePat[] = {
        0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xC1, 0xEB, 0x09,
        0x48, 0x8D
    };
    const char pteMask[] = "xxx????xxxxxx";

    // 优先在 .text 节中高效、精确查找，避免全镜像跨节扫描
    ULONG textSectionSize = 0;
    PUCHAR textBase = (PUCHAR)KernelHelperGetSectionAddress(g_KernelBase, ".text", &textSectionSize);
    PUCHAR match = NULL;

    if (textBase != NULL && textSectionSize > 0) {
        match = KernelHelperFindPattern(textBase, textSectionSize, ptePat, pteMask);
    }
    if (match == NULL) {
        match = KernelHelperFindPattern((PUCHAR)g_KernelBase, g_KernelSize, ptePat, pteMask);
    }
    if (match != NULL) {
        LONG disp = *(PLONG)(match + 3);
        PULONG_PTR pMmPteBaseVar = (PULONG_PTR)(match + 7 + disp);
        if (MmIsAddressValid(pMmPteBaseVar)) {
            g_MmPteBase = *pMmPteBaseVar;

            // 基于自引用索引计算四级页表基址 (PML4 -> PDPT -> PD -> PT)
            ULONG_PTR selfRefIndex = (g_MmPteBase >> 39) & 0x1FF;
            ULONG_PTR base = g_MmPteBase;
            base |= (selfRefIndex << 30);
            g_MmPdeBase = base;
            base |= (selfRefIndex << 21);
            g_MmPdpteBase = base;
            base |= (selfRefIndex << 12);
            g_MmPml4eBase = base;

            PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "[KernelHelper] 成功动态定位硬件页表基址:\n"
                "  -> MmPteBase:   %p (变量地址: %p, 自引用索引: 0x%llX)\n"
                "  -> MmPdeBase:   %p\n"
                "  -> MmPdpteBase: %p\n"
                "  -> MmPml4eBase: %p\n",
                (PVOID)g_MmPteBase, pMmPteBaseVar, (unsigned long long)selfRefIndex,
                (PVOID)g_MmPdeBase, (PVOID)g_MmPdpteBase, (PVOID)g_MmPml4eBase));
            return;
        }
    }

    // 回退方案：通过 MmGetVirtualForPhysical 特征定位或经验基址
    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
        "[KernelHelper] 未能直接匹配 MmPteBase 特征，使用备用自省机制\n"));
}

VOID ResolvePoolAndSystemPteInfo(VOID)
{
    if (g_KernelBase == NULL || g_KernelSize == 0) {
        return;
    }

    ULONG textSectionSize = 0;
    PUCHAR textBase = (PUCHAR)KernelHelperGetSectionAddress(g_KernelBase, ".text", &textSectionSize);

    // 1. 定位 PoolBigPageTable 和 PoolBigPageTableSize
    // 特征 1 (ExProtectPoolEx):
    //   mov r8, cs:PoolBigPageTableSize  ; 4C 8B 05 [disp32]
    //   mov r9, cs:PoolBigPageTable      ; 4C 8B 0D [disp32]
    //   movzx edi, al                    ; 0F B6
    const UCHAR poolBigPat1[] = {
        0x4C, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0xB6
    };
    const char poolBigMask1[] = "xxx????xxx????xx";

    // 特征 2 (ExQueryBigPoolTag 备选):
    //   mov rbx, cs:PoolBigPageTable     ; 48 8B 1D [disp32]
    //   mov rdi, rdx                     ; 48 8B FA
    //   mov r9, cs:PoolBigPageTableSize  ; 4C 8B 0D [disp32]
    const UCHAR poolBigPat2[] = {
        0x48, 0x8B, 0x1D, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0xFA,
        0x4C, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00
    };
    const char poolBigMask2[] = "xxx????xxxxx????";

    PUCHAR match = NULL;
    if (textBase != NULL && textSectionSize > 0) {
        match = KernelHelperFindPattern(textBase, textSectionSize, poolBigPat1, poolBigMask1);
    }
    if (match == NULL) {
        match = KernelHelperFindPattern((PUCHAR)g_KernelBase, g_KernelSize, poolBigPat1, poolBigMask1);
    }

    if (match != NULL) {
        LONG dispSize = *(PLONG)(match + 3);
        PULONG pSizeVar = (PULONG)(match + 7 + dispSize);
        LONG dispTable = *(PLONG)(match + 10);
        PPOOL_TRACKER_BIG_PAGES* ppTableVar = (PPOOL_TRACKER_BIG_PAGES*)(match + 14 + dispTable);

        if (MmIsAddressValid(pSizeVar) && MmIsAddressValid(ppTableVar)) {
            g_PoolBigPageTableSizeVar = pSizeVar;
            g_PoolBigPageTableVar = ppTableVar;
        }
    } else {
        if (textBase != NULL && textSectionSize > 0) {
            match = KernelHelperFindPattern(textBase, textSectionSize, poolBigPat2, poolBigMask2);
        }
        if (match == NULL) {
            match = KernelHelperFindPattern((PUCHAR)g_KernelBase, g_KernelSize, poolBigPat2, poolBigMask2);
        }
        if (match != NULL) {
            LONG dispTable = *(PLONG)(match + 3);
            PPOOL_TRACKER_BIG_PAGES* ppTableVar = (PPOOL_TRACKER_BIG_PAGES*)(match + 7 + dispTable);
            LONG dispSize = *(PLONG)(match + 13);
            PULONG pSizeVar = (PULONG)(match + 17 + dispSize);

            if (MmIsAddressValid(pSizeVar) && MmIsAddressValid(ppTableVar)) {
                g_PoolBigPageTableSizeVar = pSizeVar;
                g_PoolBigPageTableVar = ppTableVar;
            }
        }
    }

    if (g_PoolBigPageTableVar != NULL && *g_PoolBigPageTableVar != NULL &&
        g_PoolBigPageTableSizeVar != NULL && *g_PoolBigPageTableSizeVar > 0) {
        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[KernelHelper] 成功定位 PoolBigPageTable: 变量地址=%p (当前首地址=%p, 容量=%lu 项)\n",
            g_PoolBigPageTableVar, *g_PoolBigPageTableVar, *g_PoolBigPageTableSizeVar));
    } else {
        PgPrintErr("[KernelHelper] 未能定位 PoolBigPageTable\n");
    }

    // 2. 定位 SystemPtes (Independent Pages 独立页面管理的 _MI_SYSTEM_PTE_TYPE)
    // 优先在常驻物理内存且永不换出的 .text 节中扫描引用 nt!MiState.SystemPtes 的调用点:
    // 特征 1 (MmMapLockedPagesSpecifyCache):
    //   lea rcx, SystemPtes     ; 48 8D 0D [disp32]
    //   call MiReservePtes      ; E8 [disp32]
    const UCHAR sysPtePat1[] = {
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
        0xE8, 0x00, 0x00, 0x00, 0x00
    };
    const char sysPteMask1[] = "xxx????x????";

    if (textBase != NULL && textSectionSize > 0) {
        PUCHAR curScan = textBase;
        ULONG curSize = textSectionSize;
        while (curSize > sizeof(sysPtePat1)) {
            PUCHAR pMatch = KernelHelperFindPattern(curScan, curSize, sysPtePat1, sysPteMask1);
            if (pMatch == NULL) {
                break;
            }
            LONG disp = *(PLONG)(pMatch + 3);
            PUCHAR pCandidate = pMatch + 7 + disp;
            if (KernelHelperIsCanonicalAddress(pCandidate) &&
                MmIsAddressValid(pCandidate) &&
                MmIsAddressValid(pCandidate + 0x40)) {
                // 严格校验 VaType 是否为 MiVaSystemPtes (9)
                ULONG vaType = *(PULONG)(pCandidate + 0x1C);
                if (vaType == 9) { // MiVaSystemPtes
                    ULONG_PTR basePte = *(PULONG_PTR)(pCandidate + 0x10);
                    ULONG_PTR totalPtes = *(PULONG_PTR)(pCandidate + 0x38);
                    if (basePte != 0 && KernelHelperIsCanonicalAddress((PVOID)basePte) &&
                        totalPtes > 0 && totalPtes < 0x10000000ULL) {
                        g_SystemPteBase = basePte;
                        g_TotalSystemPtes = totalPtes;
                        PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[KernelHelper] 成功定位 SystemPtes (_MI_SYSTEM_PTE_TYPE at %p): BasePte=%p, TotalPtes=0x%llX\n",
                            pCandidate, (PVOID)g_SystemPteBase, (unsigned long long)g_TotalSystemPtes));
                        break;
                    }
                }
            }
            ULONG step = (ULONG)(pMatch - curScan) + 1;
            curScan += step;
            curSize -= step;
        }
    }

    if (g_SystemPteBase == 0) {
        // 备用方案：若 .text 节未命中，尝试 PAGE 节特征 (MmAllocateIndependentPagesEx)
        const UCHAR sysPtePat2[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0x8B, 0xD6,
            0x0F, 0x11
        };
        const char sysPteMask2[] = "xxx????xxxx";

        ULONG pageSectionSize = 0;
        PUCHAR pageBase = (PUCHAR)KernelHelperGetSectionAddress(g_KernelBase, "PAGE", &pageSectionSize);
        match = NULL;
        if (pageBase != NULL && pageSectionSize > 0) {
            match = KernelHelperFindPattern(pageBase, pageSectionSize, sysPtePat2, sysPteMask2);
        }
        if (match == NULL) {
            match = KernelHelperFindPattern((PUCHAR)g_KernelBase, g_KernelSize, sysPtePat2, sysPteMask2);
        }

        if (match != NULL) {
            LONG disp = *(PLONG)(match + 3);
            PUCHAR pSysPteType = match + 7 + disp;
            if (MmIsAddressValid(pSysPteType) && MmIsAddressValid(pSysPteType + 0x40)) {
                ULONG vaType = *(PULONG)(pSysPteType + 0x1C);
                if (vaType == 9) {
                    g_SystemPteBase = *(PULONG_PTR)(pSysPteType + 0x10);
                    g_TotalSystemPtes = *(PULONG_PTR)(pSysPteType + 0x38);
                    PgTrace((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[KernelHelper] 成功定位 SystemPtes (PAGE 节备选): BasePte=%p, TotalPtes=0x%llX\n",
                        (PVOID)g_SystemPteBase, (unsigned long long)g_TotalSystemPtes));
                }
            }
        }
    }

    if (g_SystemPteBase == 0) {
        PgPrintErr("[KernelHelper] 未能定位 SystemPtes 特征\n");
    }
}

PULONG_PTR KernelHelperGetPte(_In_ PVOID VirtualAddress)
{
    if (g_MmPteBase == 0 || !KernelHelperIsCanonicalAddress(VirtualAddress)) {
        return NULL;
    }

    ULONG_PTR pteAddr = g_MmPteBase + (((ULONG_PTR)VirtualAddress >> 9) & 0x7FFFFFFFF8ULL);
    if (!MmIsAddressValid((PVOID)pteAddr)) {
        return NULL;
    }

    return (PULONG_PTR)pteAddr;
}

BOOLEAN KernelHelperIsMemoryRwx(_In_ PVOID VirtualAddress)
{
    PULONG_PTR pPte = KernelHelperGetPte(VirtualAddress);
    if (pPte == NULL) {
        return FALSE;
    }

    __try {
        ULONG_PTR pteVal = *pPte;
        // PTE 属性标志位：
        //   Bit 0: Present (有效驻留)
        //   Bit 1: Read/Write (可写)
        //   Bit 63: NoExecute (不可执行 / NX 保护)
        BOOLEAN present = (pteVal & 1) != 0;
        BOOLEAN writable = ((pteVal >> 1) & 1) != 0;
        BOOLEAN noExecute = ((pteVal >> 63) & 1) != 0;

        return (present && writable && !noExecute);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

BOOLEAN KernelHelperIsMemoryExecutable(_In_ PVOID VirtualAddress)
{
    if (VirtualAddress == NULL || !KernelHelperIsCanonicalAddress(VirtualAddress)) {
        return FALSE;
    }

    PULONG_PTR pPte = KernelHelperGetPte(VirtualAddress);
    if (pPte == NULL) {
        // 无法解析硬件 PTE 时，必须保守返回 FALSE，严禁退化为 MmIsAddressValid！
        // 否则合法的只读/读写数据池 (NonPagedPool/Stack) 会被误判为可执行代码
        return FALSE;
    }

    __try {
        ULONG_PTR pteVal = *pPte;
        BOOLEAN present = (pteVal & 1) != 0;
        BOOLEAN noExecute = ((pteVal >> 63) & 1) != 0;
        return (present && !noExecute);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

BOOLEAN KernelHelperWriteReadOnlyMemory(
    _In_ PVOID Destination,
    _In_ const VOID* Source,
    _In_ SIZE_T Length)
{
    if (Destination == NULL || Source == NULL || Length == 0) {
        return FALSE;
    }

    PMDL mdl = IoAllocateMdl(Destination, (ULONG)Length, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        return FALSE;
    }

    PVOID mapped = NULL;
    BOOLEAN success = FALSE;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

        if (mapped != NULL) {
            MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
            RtlCopyMemory(mapped, Source, Length);
            success = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        success = FALSE;
    }

    if (mapped != NULL) {
        MmUnmapLockedPages(mapped, mdl);
    }

    if (mdl != NULL) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
    }

    return success;
}
