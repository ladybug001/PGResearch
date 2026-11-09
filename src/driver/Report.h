#pragma once
#include "PgTypes.h"

void PgReportInitialize(const PG_CONFIG *Config, unsigned long long RunId);
void PgReportReleaseTracking(void);
const PG_CONFIG *PgReportConfig(void);
unsigned long long PgReportRunId(void);
PG_ITEM_RESULT *PgReportGetItem(PG_ITEM_ID Id);
void PgReportBegin(PG_ITEM_ID Id);
void PgReportEnd(PG_ITEM_ID Id);
void PgReportPartial(PG_ITEM_ID Id, const char *Reason);
void PgReportError(PG_ITEM_ID Id, const char *Reason);
void PgReportErrorIf(PG_ITEM_ID Id, int Condition, const char *Reason);
void PgReportPartialIf(PG_ITEM_ID Id, int Condition, const char *Reason);
void PgReportTimerAction(void *Routine, void *Independent1, void *Independent2);
void PgReportTimerScopeSkip(int Condition, const char *Reason);
void PgReportIndependentDpc(void *Object, unsigned long Cpu, const char *Source);
void PgReportRwx(unsigned long Total, unsigned long Unbacked, unsigned long Module);
void PgReportRwxSkip(void);
void PgReportRwxError(void);
const unsigned long *PgReportRwxCounts(void);
void PgReportFound(PG_ITEM_ID Id, PG_OBSERVATION Observation, void *Object, unsigned long Cpu, void *Tid, const char *Reason);
/* Start and End are inclusive virtual addresses of one distinct RWX range. */
void PgReportFoundRwxRange(void *Start, void *End);
void PgReportScanned(PG_ITEM_ID Id, unsigned long Count);
void PgReportAction(PG_ITEM_ID Id, PG_ACTION Action, const char *Reason);
void PgReportRestore(PG_ITEM_ID Id, PG_RESTORE Restore);
void PgReportTarget(PG_ITEM_ID Id, void *Timeout);
PG_ITEM_ID PgReportTargetItem(void *Timeout);
int PgReportHasCoverageGap(void);
const char *PgReportItemName(PG_ITEM_ID Id);
const char *PgReportCoverageName(PG_COVERAGE Value);
const char *PgReportObservationName(PG_OBSERVATION Value);
const char *PgReportActionName(PG_ACTION Value);
const char *PgReportRestoreName(PG_RESTORE Value);
void PgReportPrint(void);
void PgReportPrintConfiguration(void);
