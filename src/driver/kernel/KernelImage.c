#include "KernelState.h"

// -----------------------------------------------------------------------------
// 页有效性缓存: DPC/定时器扫描按槽高频调用 MmIsAddressValid (每次页表级查询)。
// 以 4KB 页为粒度缓存判定结果, 同页内后续查询零成本。512 槽环形, 只缓存
// "有效"结果 —— 无效页可能是瞬态 (页面切换中), 不缓存以保证最终能观察到恢复。
// -----------------------------------------------------------------------------
#define PG_VALID_PAGE_CACHE_SLOTS 512
static struct {
    ULONG_PTR PageVa;
} g_ValidPageCache[PG_VALID_PAGE_CACHE_SLOTS] = { 0 };
static ULONG g_ValidPageCacheCursor = 0;

BOOLEAN KernelHelperIsPageValidCached(_In_ PVOID Address)
{
    ULONG_PTR page = (ULONG_PTR)Address & ~((ULONG_PTR)PAGE_SIZE - 1);

    for (ULONG i = 0; i < PG_VALID_PAGE_CACHE_SLOTS; i++) {
        if (g_ValidPageCache[i].PageVa == page) {
            return TRUE; // 已知有效
        }
    }

    if (!MmIsAddressValid(Address)) {
        return FALSE; // 无效不缓存 (可能瞬态)
    }

    g_ValidPageCache[g_ValidPageCacheCursor].PageVa = page;
    g_ValidPageCacheCursor = (g_ValidPageCacheCursor + 1) % PG_VALID_PAGE_CACHE_SLOTS;
    return TRUE;
}
BOOLEAN KernelHelperIsCanonicalAddress(_In_ PVOID Address)
{
    ULONG64 addr = (ULONG64)Address;
    ULONG64 bit47 = (addr >> 47) & 1;
    // x64 要求：若第 47 位为 1，则 48~63 位必须全为 1 (0xFFFF)；若为 0，则全为 0 (0x0000)
    return (bit47 * 0xFFFFULL) == (addr >> 48);
}

PVOID KernelHelperMakeCanonicalAddress(_In_ PVOID Address)
{
    ULONG_PTR trimmed = ((ULONG_PTR)Address << 16) >> 16;
    if ((trimmed >> 47) & 1) {
        trimmed |= 0xFFFF000000000000ULL;
    }
    return (PVOID)trimmed;
}

PVOID KernelHelperGetSectionAddress(
    _In_ PVOID ModuleBase,
    _In_ const char* SectionName,
    _Out_ PULONG OutSectionSize)
{
    if (ModuleBase == NULL || SectionName == NULL) {
        return NULL;
    }

    __try {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        if (!MmIsAddressValid(dosHeader) || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return NULL;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        if (!MmIsAddressValid(ntHeaders) || ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return NULL;
        }

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
            if (!MmIsAddressValid(section)) {
                break;
            }
            if (_strnicmp((const char*)section->Name, SectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
                if (OutSectionSize != NULL) {
                    *OutSectionSize = section->Misc.VirtualSize;
                }
                return (PUCHAR)ModuleBase + section->VirtualAddress;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return NULL;
}

PUCHAR KernelHelperFindPattern(
    _In_ PUCHAR BaseAddress,
    _In_ ULONG Size,
    _In_ const UCHAR* Pattern,
    _In_ const char* Mask)
{
    if (BaseAddress == NULL || Size == 0 || Pattern == NULL || Mask == NULL) {
        return NULL;
    }

    SIZE_T maskLen = strlen(Mask);
    if (maskLen == 0 || Size < maskLen) {
        return NULL;
    }

    SIZE_T maxIndex = Size - maskLen;
    SIZE_T i = 0;

    __try {
        while (i <= maxIndex) {
            PUCHAR currentAddr = &BaseAddress[i];

            // 1. 检查当前起始字节所在页面的物理驻留有效性
            // 严防跨入未映射页、保护页或系统引导后已释放的 INIT 内存段引发 0x50 BugCheck
            if (!MmIsAddressValid(currentAddr)) {
                ULONG_PTR pageOffset = (ULONG_PTR)currentAddr & (PAGE_SIZE - 1);
                ULONG_PTR skipBytes = PAGE_SIZE - pageOffset;
                i += skipBytes;
                continue;
            }

            // 2. 若特征码跨越 4KB 页面边界，核查尾部字节所在页面的有效性
            PUCHAR endAddr = currentAddr + maskLen - 1;
            if (((ULONG_PTR)currentAddr & ~(PAGE_SIZE - 1)) != ((ULONG_PTR)endAddr & ~(PAGE_SIZE - 1))) {
                if (!MmIsAddressValid(endAddr)) {
                    ULONG_PTR pageOffset = (ULONG_PTR)currentAddr & (PAGE_SIZE - 1);
                    ULONG_PTR skipBytes = PAGE_SIZE - pageOffset;
                    i += skipBytes;
                    continue;
                }
            }

            // 3. 当前页有效：在页内安全边界窗口中执行快速连续比对
            ULONG_PTR bytesInCurrentPage = PAGE_SIZE - ((ULONG_PTR)currentAddr & (PAGE_SIZE - 1));
            SIZE_T stepLimit = (bytesInCurrentPage < (maxIndex - i + 1)) ? bytesInCurrentPage : (maxIndex - i + 1);

            for (SIZE_T step = 0; step < stepLimit; step++, i++) {
                PUCHAR scanPtr = &BaseAddress[i];
                BOOLEAN match = TRUE;
                for (SIZE_T j = 0; j < maskLen; j++) {
                    if (Mask[j] != '?' && Pattern[j] != scanPtr[j]) {
                        match = FALSE;
                        break;
                    }
                }
                if (match) {
                    return scanPtr;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    return NULL;
}

// -----------------------------------------------------------------------------
// 模块反查缓存: 栈扫描按槽高频调用本函数, 未命中时需遍历整个模块链表。
// 以 4KB 页为粒度缓存判定结果 (同页内的地址归属必然一致), 未命中页记录后免遍历。
// -----------------------------------------------------------------------------
#define PG_MODULE_CACHE_SLOTS 512
static struct {
    ULONG_PTR PageVa;       // 4KB 页基址 (0 = 空槽)
    BOOLEAN HasModule;
} g_ModulePageCache[PG_MODULE_CACHE_SLOTS] = { 0 };
static ULONG g_ModuleCacheCursor = 0;

static BOOLEAN ModulePageCacheLookup(ULONG_PTR Address, BOOLEAN *HasModule)
{
    ULONG_PTR page = Address & ~((ULONG_PTR)PAGE_SIZE - 1);
    for (ULONG i = 0; i < PG_MODULE_CACHE_SLOTS; i++) {
        if (g_ModulePageCache[i].PageVa == page) {
            *HasModule = g_ModulePageCache[i].HasModule;
            return TRUE;
        }
    }
    return FALSE;
}

static VOID ModulePageCacheStore(ULONG_PTR Address, BOOLEAN HasModule)
{
    ULONG_PTR page = Address & ~((ULONG_PTR)PAGE_SIZE - 1);
    g_ModulePageCache[g_ModuleCacheCursor].PageVa = page;
    g_ModulePageCache[g_ModuleCacheCursor].HasModule = HasModule;
    g_ModuleCacheCursor = (g_ModuleCacheCursor + 1) % PG_MODULE_CACHE_SLOTS;
}
BOOLEAN KernelHelperFindModuleByAddress(
    _In_ PVOID Address,
    _Out_ PUNICODE_STRING OutModuleName,
    _Out_ PULONG_PTR OutOffset)
{
    if (g_DriverObject == NULL || g_DriverObject->DriverSection == NULL || Address == NULL) {
        return FALSE;
    }

    if (!KernelHelperIsCanonicalAddress(Address)) {
        return FALSE;
    }

    // 页粒度缓存: 未命中模块的页免于每次全链表遍历 (栈扫描热点路径)
    BOOLEAN cachedHasModule = FALSE;
    if (ModulePageCacheLookup((ULONG_PTR)Address, &cachedHasModule)) {
        if (!cachedHasModule) {
            return FALSE; // 缓存判定为无归属, 调用方按未背书处理
        }
        // 命中归属缓存: 仍需遍历一次取模块名/偏移 (命中页极少, 开销可忽略)
    }

    __try {
        PKLDR_DATA_TABLE_ENTRY firstEntry = (PKLDR_DATA_TABLE_ENTRY)g_DriverObject->DriverSection;
        PLIST_ENTRY head = &firstEntry->InLoadOrderLinks;
        PLIST_ENTRY curr = head;

        do {
            PKLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (MmIsAddressValid(entry) && entry->DllBase != NULL) {
                ULONG_PTR base = (ULONG_PTR)entry->DllBase;
                ULONG_PTR size = entry->SizeOfImage;
                ULONG_PTR target = (ULONG_PTR)Address;

                if (target >= base && target < base + size) {
                    ModulePageCacheStore((ULONG_PTR)Address, TRUE);
                    *OutModuleName = entry->BaseDllName;
                    *OutOffset = target - base;
                    return TRUE;
                }
            }
            curr = curr->Flink;
        } while (curr != head && curr != NULL && MmIsAddressValid(curr));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    ModulePageCacheStore((ULONG_PTR)Address, FALSE); // 未命中: 记入缓存免后续全遍历
    return FALSE;
}

// -----------------------------------------------------------------------------
// 极简安全 x64 指令长度解码 (跨页校验, 用于序言搬迁长度计算)
// -----------------------------------------------------------------------------
static UCHAR KernelHelperSafeFetchByte(_In_ const UCHAR* Code, _In_ ULONG len, _Inout_ ULONG_PTR* CurPage, _Out_ BOOLEAN* Ok)
{
    ULONG_PTR byteAddr = (ULONG_PTR)(Code + len);
    ULONG_PTR page = byteAddr & ~((ULONG_PTR)PAGE_SIZE - 1);
    if (page != *CurPage) {
        if (!MmIsAddressValid((PVOID)byteAddr)) {
            *Ok = FALSE;
            return 0xFF;
        }
        *CurPage = page;
    }
    *Ok = TRUE;
    return Code[len];
}

ULONG KernelHelperDecodeInstructionLength(_In_ const UCHAR* Code)
{
    ULONG len = 0;
    ULONG_PTR curPage = 0;
    BOOLEAN ok = FALSE;

    for (;;) {
        UCHAR b = KernelHelperSafeFetchByte(Code, len, &curPage, &ok);
        if (!ok) return 0;
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            len++;
            if (len > 15) return 0;
            continue;
        }
        break;
    }

    UCHAR b = KernelHelperSafeFetchByte(Code, len, &curPage, &ok);
    if (!ok) return 0;
    if ((b & 0xF0) == 0x40) {
        len++;
    }

    UCHAR op = KernelHelperSafeFetchByte(Code, len, &curPage, &ok);
    if (!ok) return 0;
    len++;

    if (op == 0x0F) {
        UCHAR op2 = KernelHelperSafeFetchByte(Code, len, &curPage, &ok);
        if (!ok) return 0;
        len++;
        if (op2 >= 0x80 && op2 <= 0x8F) {
            return len + 4;
        }
        UCHAR modrm = KernelHelperSafeFetchByte(Code, len, &curPage, &ok);
        if (!ok) return 0;
        len++;
        if ((modrm >> 6) == 1) return len + 1;
        if ((modrm >> 6) == 2) return len + 4;
        return len;
    }

    if ((op & 0xF0) == 0x50 || (op & 0xF8) == 0x58) {
        return len;
    }
    if (op == 0xC3 || op == 0x90 || op == 0xCC) {
        return len;
    }

    UCHAR modrm = KernelHelperSafeFetchByte(Code, len, &curPage, &ok);
    if (!ok) return 0;
    len++;

    if (op == 0x8B || op == 0x89 || op == 0x03 || op == 0x01 ||
        op == 0x3B || op == 0x2B || op == 0x0B || op == 0x23 ||
        op == 0x33 || op == 0x39 || op == 0x85 ||
        op == 0x8D || op == 0x63) {
        UCHAR mod = (modrm >> 6) & 3;
        UCHAR rm = modrm & 7;
        if (mod != 3) {
            if (rm == 4) {
                UCHAR sib = KernelHelperSafeFetchByte(Code, len, &curPage, &ok);
                if (!ok) return 0;
                len++;
            }
            if (mod == 1) return len + 1;
            if (mod == 2 || (mod == 0 && rm == 5)) return len + 4;
        }
        return len;
    }

    if (op == 0x81 || op == 0x83) {
        UCHAR mod = (modrm >> 6) & 3;
        UCHAR rm = modrm & 7;
        if (mod != 3) {
            if (rm == 4) {
                UCHAR sib = KernelHelperSafeFetchByte(Code, len, &curPage, &ok);
                if (!ok) return 0;
                len++;
            }
            if (mod == 1) return len + 1 + ((op == 0x81) ? 4 : 1);
            if (mod == 2 || (mod == 0 && rm == 5)) return len + 4 + ((op == 0x81) ? 4 : 1);
        }
        return len + ((op == 0x81) ? 4 : 1);
    }

    if (op == 0xB8 || op == 0xB9 || op == 0xBA || op == 0xBB ||
        op == 0xBC || op == 0xBD || op == 0xBE || op == 0xBF) {
        return len + 4;
    }

    if (op == 0xC7) {
        UCHAR mod = (modrm >> 6) & 3;
        UCHAR rm = modrm & 7;
        if (mod != 3) {
            if (rm == 4) {
                UCHAR sib = KernelHelperSafeFetchByte(Code, len, &curPage, &ok);
                if (!ok) return 0;
                len++;
            }
            if (mod == 1) return len + 1 + 4;
            if (mod == 2 || (mod == 0 && rm == 5)) return len + 4 + 4;
        }
        return len + 4;
    }

    return 0;
}
