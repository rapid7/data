# IDA scripts

These scripts aim to find and process metadata used by the Codesys V3 runtime.
The runtime is divided into components that are managhed by a component manager.
This manager is initialized during startup by looping over a table that contains
pointers to entry functions for each component. Inside of this entry functions,
pointers to other functions into the component itself and also to functions
of this component are exchanged.

The scripts try to find these pointers and rename the functions according to
component names and struct entries.

This script was written for Codesys V3.5.15.10. Newer versions might be different.
Also the HRAST patterns might not match all available architectures. This is
research code and you most likely need to adapt it. Don't expect it to just work.

## How to use this thing

1. Switch IDA 7 to Python 3 if necessary
2. `git clone https://github.com/sibears/HRAST.git`
3. Apply `HRAST.patch` to HRAST subfolder
4. Load codesys binary
5. Find `PlcStart`
6. In PlcStart is a call to `CMInit2`
7. 2nd parameter to this function is the component list
8. Add the following structs:

```
// NOTE: Types might be wrong

struct CMP_EXT_FUNCTION_REF {
    void *pfExtCall;
    const char *pszExtCallName;
    int signature;
    int version;
};

CMP_EXT_FUNCTION_REF CM_ExternalsTable {
    {CM_cmunloadcomponent, "cmunloadcomponent", 0, 0},
    {CM_cmloadcomponent, "cmloadcomponent", 0, 0},
    {CM_cmutlwtoutf8, "cmutlwtoutf8", 0xAE6E95C8, 0x3050D00},
    ...
    {NULL, "", 0, 0},
}

struct INIT_STRUCT {
    int CmpId;
    int (*pfExportFunctions)(void);
    int (*pfImportFunctions)(void);
    int (*pfGetVersion)(void);
    void *(*pfCreateInstance)(_DWORD cid, _DWORD *pResult);
    _DWORD (*pfDeleteInstance)(void *pIBase);
    int (*pfHookFunction)(_DWORD ulHook, _DWORD *ulParam1, _DWORD *ulParam2);
    _DWORD (*pfCMRegisterAPI)(CMP_EXT_FUNCTION_REF *pExpTable, _DWORD *dummy, int bExternalLibrary, _DWORD cmpId);
    _DWORD (*pfCMGetAPI)(char *pszAPIName, void *ppfAPIFunction, _DWORD ulSignatureID);
    _DWORD (*pfCMCallHook)(_DWORD ulHook, _DWORD *ulParam1, _DWORD *ulParam2, int bReverse);
    void *(*pfCMRegisterClass)(_DWORD CmpId, _DWORD ClassId);
    void *(*pfCMCreateInstance)(_DWORD cid, _DWORD *pResult);
    _DWORD (*pfCMRegisterAPI2)(const char *pszAPIName, void *pfAPIFunction, int bExternalLibrary, _DWORD ulSignatureID, _DWORD ulVersion);
    _DWORD (*pfCMGetAPI2)(char *pszAPIName, void *ppfAPIFunction, int bExternalLibrary, _DWORD ulSignatureID, _DWORD ulVersion);
    _DWORD (*pfCMDeleteInstance2)(_DWORD ClassId, void *pIBase);
};


struct StaticComponent {
    char *name;
    int (*function)(INIT_STRUCT *pInitStruct);
    int unknown;
};

StaticComponent[] SysMainComponentList = {
    {"CM", CM__Entry, 0},
    {"CmpAlarmManager", CmpAlarmManager__Entry, 0},
    {"CmpApp", CmpApp__Entry, 0},
    ...
    {NULL, NULL, 0},
}
```

9. Alt + F7 and select `ida_codesys_helper.py`
10. Execute `do_work(0x12345678)` where the parameter is the address of the component list
11. Watch the magic happen, crash and burn!

It's a bit hard to unterstand how to use all of this if you didn't load any code
into IDA yet and have a rough overview about how the runtime starts and what the
component management looks like. So go ahead! Load and executable and start digging!
