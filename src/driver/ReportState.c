#include <limits.h>
#include <string.h>
#ifdef _KERNEL_MODE
#include <ntddk.h>
#define PG_REPORT_POOL_TAG 'peRP'
#else
#include <stdlib.h>
#endif
#include "Report.h"

static PG_CONFIG g_Config;
static PG_ITEM_RESULT g_Items[PgItemCount];
static unsigned long long g_RunId;
static struct { void *Timeout; PG_ITEM_ID Id; } g_Targets[16];
static unsigned long g_TargetCount;
/* state: 0 unavailable, 1 completed, 2 partial; then counts and skipped/exception totals */
static unsigned long g_RwxCounts[6];
#define PG_INLINE_OBJECT_CAPACITY 64
typedef struct {
    void *InlineObjects[PG_INLINE_OBJECT_CAPACITY];
    void **ExpandedObjects;
    unsigned long Count, Capacity;
} PG_OBJECT_TRACKER;
static PG_OBJECT_TRACKER g_MatchedObjects[PgItemCount];
static PG_OBJECT_TRACKER g_LocatedObjects[PgItemCount];

static void PgReportFreeObjects(void **Objects)
{
    if (!Objects) return;
#ifdef _KERNEL_MODE
    ExFreePoolWithTag(Objects, PG_REPORT_POOL_TAG);
#else
    free(Objects);
#endif
}

void PgReportReleaseTracking(void)
{
    unsigned long i;
    for (i = 0; i < PgItemCount; ++i) {
        PgReportFreeObjects(g_MatchedObjects[i].ExpandedObjects);
        PgReportFreeObjects(g_LocatedObjects[i].ExpandedObjects);
    }
    memset(g_MatchedObjects, 0, sizeof(g_MatchedObjects));
    memset(g_LocatedObjects, 0, sizeof(g_LocatedObjects));
}

static int PgReportGrowTracker(PG_OBJECT_TRACKER *Tracker)
{
    unsigned long capacity;
    void **objects;
    if (Tracker->Capacity > ULONG_MAX / 2) return 0;
    capacity = Tracker->Capacity ? Tracker->Capacity * 2 : PG_INLINE_OBJECT_CAPACITY * 2;
    if (capacity > (size_t)-1 / sizeof(*objects)) return 0;
#ifdef _KERNEL_MODE
#pragma warning(suppress: 4996)
    objects = ExAllocatePoolWithTag(NonPagedPoolNx, capacity * sizeof(*objects), PG_REPORT_POOL_TAG);
#else
    objects = malloc(capacity * sizeof(*objects));
#endif
    if (!objects) return 0;
    memcpy(objects, Tracker->ExpandedObjects ? Tracker->ExpandedObjects : Tracker->InlineObjects,
        Tracker->Count * sizeof(*objects));
    PgReportFreeObjects(Tracker->ExpandedObjects);
    Tracker->ExpandedObjects = objects;
    Tracker->Capacity = capacity;
    return 1;
}

void PgReportInitialize(const PG_CONFIG *Config, unsigned long long RunId)
{
    unsigned long i;
    g_Config = *Config;
    g_RunId = RunId;
    memset(g_Items, 0, sizeof(g_Items));
    memset(g_Targets, 0, sizeof(g_Targets));
    g_TargetCount = 0;
    memset(g_RwxCounts, 0, sizeof(g_RwxCounts));
    PgReportReleaseTracking();
    for (i = 0; i < PgItemCount; ++i) {
        int enabled = Config->BypassEnabled;
        g_Items[i].Action = enabled ? PgActionSkipped : PgActionDisabled;
        g_Items[i].ActionReason = enabled ? "no applicable target / not executed" : "bypass disabled";
        g_Items[i].CoverageReason = "not scanned";
        g_Items[i].ObservationReason = "no observation";
    }
    g_Items[PgMethod6].Coverage = PgUnsupported;
    g_Items[PgMethod6].CoverageReason = "not implemented in original project";
    g_Items[PgMethod6].ActionReason = "no original implementation";
}
const PG_CONFIG *PgReportConfig(void) { return &g_Config; }
unsigned long long PgReportRunId(void) { return g_RunId; }
PG_ITEM_RESULT *PgReportGetItem(PG_ITEM_ID Id) { return (unsigned int)Id < PgItemCount ? &g_Items[Id] : NULL; }
void PgReportBegin(PG_ITEM_ID Id)
{
    PG_ITEM_RESULT *r = PgReportGetItem(Id);
    if (!r || r->Coverage == PgUnsupported) return;
    r->Coverage = PgComplete;
    r->CoverageReason = "within original scan scope";
}
void PgReportEnd(PG_ITEM_ID Id)
{
    PG_ITEM_RESULT *r = PgReportGetItem(Id);
    if (r && r->Coverage == PgComplete && r->Observation == PgUnknown) {
        r->Observation = PgNoMatch;
        r->ObservationReason = "no match in scanned scope; not proof of absence";
    }
}
void PgReportPartial(PG_ITEM_ID Id, const char *Reason)
{
    PG_ITEM_RESULT *r = PgReportGetItem(Id);
    if (!r || r->Coverage == PgUnsupported) return;
    r->Coverage = PgPartial;
    r->CoverageReason = Reason;
}
void PgReportError(PG_ITEM_ID Id, const char *Reason)
{
    PG_ITEM_RESULT *r = PgReportGetItem(Id);
    if (!r || r->Coverage == PgUnsupported) return;
    r->Coverage = r->Matches || r->Located ? PgPartial : PgFailed;
    r->CoverageReason = Reason;
}
void PgReportErrorIf(PG_ITEM_ID Id, int Condition, const char *Reason)
{
    if (Condition) PgReportError(Id, Reason);
}
void PgReportPartialIf(PG_ITEM_ID Id, int Condition, const char *Reason)
{
    if (Condition) PgReportPartial(Id, Reason);
}
void PgReportTimerAction(void *Routine, void *Independent1, void *Independent2)
{
    PG_ITEM_ID id = Routine && (Routine == Independent1 || Routine == Independent2) ? PgIndependentTimer : PgMethod0;
    PgReportAction(id, PgActionApplied, "original timer DPC operation applied");
}
void PgReportTimerScopeSkip(int Condition, const char *Reason)
{
    if (!Condition) return;
    PgReportAction(PgMethod0, PgActionSkipped, Reason);
    PgReportAction(PgIndependentTimer, PgActionSkipped, Reason);
}
void PgReportIndependentDpc(void *Object, unsigned long Cpu, const char *Source)
{
    int scheduled = Source && (!strcmp(Source, "ActiveDpc") || !strcmp(Source, "QueuedDpc") || !strcmp(Source, "Timer-DPC"));
    PgReportFound(PgIndependentTimer, scheduled ? PgObservedActive : PgSuspected, Object, Cpu, NULL, Source ? Source : "unknown DPC source");
}
void PgReportRwx(unsigned long Total, unsigned long Unbacked, unsigned long Module)
{
    if (!g_RwxCounts[0]) g_RwxCounts[0] = 1;
    g_RwxCounts[1] = Total;
    g_RwxCounts[2] = Unbacked; g_RwxCounts[3] = Module;
}
void PgReportRwxSkip(void) { g_RwxCounts[0] = 2; ++g_RwxCounts[4]; }
void PgReportRwxError(void) { g_RwxCounts[0] = 2; ++g_RwxCounts[5]; }
const unsigned long *PgReportRwxCounts(void) { return g_RwxCounts; }
static void PgReportRecordFound(PG_ITEM_ID Id, PG_OBSERVATION Observation, void *Object,
    unsigned long Cpu, void *Tid, const char *Reason, void *RangeEnd)
{
    PG_ITEM_RESULT *r = PgReportGetItem(Id);
    unsigned long *count;
    int boundedTracking = !RangeEnd && Id != PgMethod3 && Id != PgMethod4;
    if (!r || !Object) return;
    if (Observation >= r->Observation) {
        r->Observation = Observation;
        r->ObservationReason = Reason;
    }
    count = Observation == PgLocatedOnly ? &r->Located : &r->Matches;
    if (*count == ULONG_MAX) {
        ++r->SamplesDropped;
        PgReportPartial(Id, "object count overflow; counts are a lower bound");
        return;
    }
    if (!RangeEnd) {
        PG_OBJECT_TRACKER *tracker = Observation == PgLocatedOnly ? &g_LocatedObjects[Id] : &g_MatchedObjects[Id];
        void **objects = tracker->ExpandedObjects ? tracker->ExpandedObjects : tracker->InlineObjects;
        unsigned long capacity = tracker->Capacity ? tracker->Capacity : PG_INLINE_OBJECT_CAPACITY;
        unsigned long i;
        for (i = 0; i < tracker->Count; ++i) if (objects[i] == Object) return;
        if (tracker->Count == capacity) {
            if (boundedTracking || !PgReportGrowTracker(tracker)) {
                ++r->SamplesDropped;
                PgReportPartial(Id, boundedTracking
                    ? "object tracking capacity reached; counts are a lower bound"
                    : "object tracking allocation failed; counts are a lower bound");
                return;
            }
            objects = tracker->ExpandedObjects;
        }
        objects[tracker->Count++] = Object;
    }
    ++*count;
    if (r->SampleCount < PG_EVIDENCE_LIMIT) {
        PG_EVIDENCE *e = &r->Samples[r->SampleCount++];
        e->Object = Object; e->Cpu = Cpu; e->Tid = Tid;
        e->RangeEnd = RangeEnd;
        e->Observation = Observation; e->Reason = Reason;
    } else {
        ++r->SamplesDropped;
        if (boundedTracking) PgReportPartial(Id, "evidence sample capacity reached; unique hit counts retained");
    }
}
void PgReportFound(PG_ITEM_ID Id, PG_OBSERVATION Observation, void *Object, unsigned long Cpu, void *Tid, const char *Reason)
{
    PgReportRecordFound(Id, Observation, Object, Cpu, Tid, Reason, NULL);
}
void PgReportFoundRwxRange(void *Start, void *End)
{
    PgReportRecordFound(PgBarricade, PgSuspected, Start, 0, NULL, "contiguous unbacked RWX range", End);
}
void PgReportScanned(PG_ITEM_ID Id, unsigned long Count)
{
    PG_ITEM_RESULT *r = PgReportGetItem(Id);
    if (r) r->Scanned += Count;
}
void PgReportAction(PG_ITEM_ID Id, PG_ACTION Action, const char *Reason)
{
    PG_ITEM_RESULT *r = PgReportGetItem(Id);
    if (!r || !g_Config.BypassEnabled) return;
    if (Action == PgActionApplied) {
        ++r->Applied;
        r->Restore = (Id == PgMethod7 || Id == PgRecoveryPath) ? PgRestoreNotAttempted : PgRestoreUnsupported;
    }
    if (Action == PgActionFailed) ++r->ActionFailures;
    if (Action == PgActionSkipped) ++r->ActionSkipped;
    r->ActionReason = Reason;
    if (r->Applied) r->Action = (r->ActionFailures || r->ActionSkipped) ? PgActionPartial : PgActionApplied;
    else if (r->ActionFailures) r->Action = PgActionFailed;
    else r->Action = Action;
}
void PgReportRestore(PG_ITEM_ID Id, PG_RESTORE Restore)
{
    PG_ITEM_RESULT *r = PgReportGetItem(Id);
    if (!r) return;
    if (r->Restore == PgRestoreUnsupported && Restore == PgRestored) r->Restore = PgRestorePartial;
    else r->Restore = Restore;
}
void PgReportTarget(PG_ITEM_ID Id, void *Timeout)
{
    if (g_TargetCount < 16) {
        g_Targets[g_TargetCount].Timeout = Timeout;
        g_Targets[g_TargetCount++].Id = Id;
    } else PgReportPartial(Id, "original suspend target capacity reached");
}
PG_ITEM_ID PgReportTargetItem(void *Timeout)
{
    unsigned long i;
    for (i = 0; i < g_TargetCount; ++i) if (g_Targets[i].Timeout == Timeout) return g_Targets[i].Id;
    return PgMethod3;
}
int PgReportHasCoverageGap(void)
{
    unsigned long i;
    for (i = 0; i < PgItemCount; ++i) if (g_Items[i].Coverage != PgComplete) return 1;
    return 0;
}
const char *PgReportItemName(PG_ITEM_ID Id)
{
    static const char *names[] = { "M0", "M2:HalReserved[7]", "M1:AcpiReserved", "M3:Thread", "M4:APC", "M5", "M6", "M7", "Independent1.Timer", "Independent2.RecoveryPath", "Barricade.RWX" };
    return (unsigned int)Id < PgItemCount ? names[Id] : "INVALID";
}
const char *PgReportCoverageName(PG_COVERAGE Value)
{
    static const char *names[] = { "NOT_RUN", "COMPLETE", "PARTIAL", "UNSUPPORTED", "FAILED" };
    return (unsigned int)Value < 5 ? names[Value] : "INVALID";
}
const char *PgReportObservationName(PG_OBSERVATION Value)
{
    static const char *names[] = { "UNKNOWN", "NO_MATCH", "LOCATED_ONLY", "SUSPECTED", "OBSERVED_ACTIVE" };
    return (unsigned int)Value < 5 ? names[Value] : "INVALID";
}
const char *PgReportActionName(PG_ACTION Value)
{
    static const char *names[] = { "DISABLED", "SKIPPED", "NOT_NEEDED", "APPLIED", "PARTIAL", "FAILED" };
    return (unsigned int)Value < 6 ? names[Value] : "INVALID";
}
const char *PgReportRestoreName(PG_RESTORE Value)
{
    static const char *names[] = { "N/A", "NOT_ATTEMPTED", "RESTORED", "PARTIAL", "FAILED", "UNSUPPORTED" };
    return (unsigned int)Value < 6 ? names[Value] : "INVALID";
}
