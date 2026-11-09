#pragma once
#include <ntddk.h>
#include "Report.h"
void PgPrint(PCSTR Format, ...);
void PgPrintErr(PCSTR Format, ...); // 摘要模式可见的错误打印 (不受 LogLevel 限制)
void PgTracePrint(ULONG Component, ULONG Level, PCSTR Format, ...);
#define PgTrace(args) PgTracePrint args
