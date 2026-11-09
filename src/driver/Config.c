#include "Config.h"

void PgConfigDefaults(PG_CONFIG *Config)
{
    Config->ScanEnabled = 1;       // 默认开启检测
    Config->BypassEnabled = 0;     // 默认关闭绕过
    Config->TriggerEnabled = 0;    // 默认关闭触发器
    Config->LogLevel = 0;          // 默认简要日志
}

int PgConfigSetValue(PG_CONFIG *Config, PG_CONFIG_KEY Key, unsigned long Value)
{
    if (Value > 1) return 0;
    switch (Key) {
    case PgConfigScan: Config->ScanEnabled = Value; break;
    case PgConfigBypass: Config->BypassEnabled = Value; break;
    case PgConfigTrigger: Config->TriggerEnabled = Value; break;
    case PgConfigLogLevel: Config->LogLevel = Value; break;
    default: return 0;
    }
    return 1;
}
