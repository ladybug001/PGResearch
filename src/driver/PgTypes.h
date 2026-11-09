#pragma once

typedef struct _PG_CONFIG {
    unsigned long ScanEnabled;       // 是否检测 Method 0/1/2/5/7 及 Independent 1/2
    unsigned long BypassEnabled;     // 综合绕过: Barricade 通杀 + 结构体主动处置/热补丁
    unsigned long TriggerEnabled;    // 主动代码破坏触发器 (测试用)
    unsigned long LogLevel;          // 0: Summary, 1: Verbose
} PG_CONFIG;

typedef enum { PgMethod0, PgMethod1, PgMethod2, PgMethod3, PgMethod4,
    PgMethod5, PgMethod6, PgMethod7, PgIndependentTimer, PgRecoveryPath,
    PgBarricade, PgItemCount } PG_ITEM_ID;
typedef enum { PgNotRun, PgComplete, PgPartial, PgUnsupported, PgFailed } PG_COVERAGE;
typedef enum { PgUnknown, PgNoMatch, PgLocatedOnly, PgSuspected, PgObservedActive } PG_OBSERVATION;
typedef enum { PgActionDisabled, PgActionSkipped, PgActionNotNeeded, PgActionApplied,
    PgActionPartial, PgActionFailed } PG_ACTION;
typedef enum { PgVerificationNotRun, PgVerified, PgStillObserved, PgInconclusive,
    PgVerificationFailed } PG_VERIFICATION;
typedef enum { PgRestoreNotApplicable, PgRestoreNotAttempted, PgRestored,
    PgRestorePartial, PgRestoreFailed, PgRestoreUnsupported } PG_RESTORE;

#define PG_EVIDENCE_LIMIT 8
typedef struct _PG_EVIDENCE {
    void *Object;
    void *RangeEnd;
    void *Tid;
    unsigned long Cpu;
    PG_OBSERVATION Observation;
    const char *Reason;
} PG_EVIDENCE;

typedef struct _PG_ITEM_RESULT {
    PG_COVERAGE Coverage;
    PG_OBSERVATION Observation;
    PG_ACTION Action;
    PG_VERIFICATION Verification;
    PG_RESTORE Restore;
    unsigned long Scanned, Matches, Located, Applied, ActionFailures, ActionSkipped;
    unsigned long SampleCount, SamplesDropped;
    unsigned long long Started, Finished;
    const char *CoverageReason, *ObservationReason, *ActionReason;
    PG_EVIDENCE Samples[PG_EVIDENCE_LIMIT];
} PG_ITEM_RESULT;
