#include "ConfigRegistry.h"
#include "Log.h"

NTSTATUS PgConfigLoad(PUNICODE_STRING RegistryPath, PG_CONFIG *Config)
{
    static const PCWSTR names[] = { L"ScanEnabled", L"BypassEnabled", L"TriggerEnabled", L"LogLevel" };
    HANDLE service = NULL, parameters = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    NTSTATUS status;
    ULONG i;
    PgConfigDefaults(Config);
    InitializeObjectAttributes(&attributes, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwOpenKey(&service, KEY_READ, &attributes);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) return STATUS_SUCCESS;
    if (!NT_SUCCESS(status)) return status;
    RtlInitUnicodeString(&name, L"Parameters");
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, service, NULL);
    status = ZwOpenKey(&parameters, KEY_READ, &attributes);
    ZwClose(service);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND) return STATUS_SUCCESS;
    if (!NT_SUCCESS(status)) return status;
    for (i = 0; i < PgConfigKeyCount; ++i) {
        UCHAR buffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + sizeof(ULONG)];
        PKEY_VALUE_PARTIAL_INFORMATION value = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
        ULONG length = 0;
        RtlInitUnicodeString(&name, names[i]);
        status = ZwQueryValueKey(parameters, &name, KeyValuePartialInformation, buffer, sizeof(buffer), &length);
        if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
            status = STATUS_SUCCESS;
            continue;
        }
        if (!NT_SUCCESS(status)) break;
        if (value->Type != REG_DWORD || value->DataLength != sizeof(ULONG) ||
            !PgConfigSetValue(Config, (PG_CONFIG_KEY)i, *(PULONG)value->Data)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }
    if (!NT_SUCCESS(status)) PgPrint("[Config] 注册表项 %ws 读取失败或无效 (status=0x%08X)\n", names[i], status);
    ZwClose(parameters);
    return status;
}
