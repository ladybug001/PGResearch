#pragma once
#include "InterruptScanner.h"
extern PVOID g_KiSwInterruptDispatchAddress;
extern UCHAR g_OriginalKiSwDispatchBytes[1];
extern BOOLEAN g_IsKiSwDispatchPatched;
extern PVOID g_KiMcaAddress;
extern UCHAR g_OriginalKiMcaBytes[2];
extern BOOLEAN g_IsKiMcaPatched;
extern PVOID* g_pMaxDataSize;
extern BOOLEAN g_KiSwDispatchVerified;
