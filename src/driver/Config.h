#pragma once
#include "PgTypes.h"
typedef enum {
    PgConfigScan,
    PgConfigBypass,
    PgConfigTrigger,
    PgConfigLogLevel,
    PgConfigKeyCount
} PG_CONFIG_KEY;
void PgConfigDefaults(PG_CONFIG *Config);
int PgConfigSetValue(PG_CONFIG *Config, PG_CONFIG_KEY Key, unsigned long Value);
