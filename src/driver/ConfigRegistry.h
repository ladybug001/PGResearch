#pragma once
#include <ntddk.h>
#include "Config.h"
NTSTATUS PgConfigLoad(PUNICODE_STRING RegistryPath, PG_CONFIG *Config);
