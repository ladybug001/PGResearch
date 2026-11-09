#pragma once
#include "Kernel.h"
VOID PgRunBypass(VOID);
BOOLEAN InterruptScannerPatchKiSwInterruptDispatch(_In_ BOOLEAN Enable);
BOOLEAN InterruptScannerPatchKiMcaRecovery(_In_ BOOLEAN Enable);
BOOLEAN InterruptScannerDestroyContext7(VOID);
BOOLEAN DpcScannerRestoreBalanceSetManagerDpc(VOID);
VOID DpcScannerNeutralizeAllProcessors(VOID);
BOOLEAN BarricadeArm(VOID);
VOID BarricadeDisarm(VOID);
ULONG BarricadeScan(VOID);
