#include <windows.h>
#include <stdio.h>
#include <string.h>

void *HookFunction(const char *moduleName, const char *functionName, void *newFunctionPtr)
{
    void *oldPointerValue = NULL;
    HMODULE hModule = GetModuleHandle(NULL);  // Gets the handle to the host executable
    if (!hModule)
    {
        printf("Failed to get module handle\n");
        return NULL;
    }

    printf("Will hook module %s function %s\n", moduleName, functionName);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pDosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDesc->Name)
    {
        LPCSTR pszModName = (LPCSTR)((LPBYTE)hModule + pImportDesc->Name);
        if (_stricmp(pszModName, moduleName) == 0)
        {
            printf("Module was found\n");
            PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((LPBYTE)hModule + pImportDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)hModule + pImportDesc->FirstThunk);
            while (pThunk->u1.Function && pOriginalThunk->u1.AddressOfData)
            {
                if (!(pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)hModule + pOriginalThunk->u1.AddressOfData);
                    printf("Function found: %s\n", pImportByName->Name);

                    if (strcmp((char*)pImportByName->Name, functionName) == 0)
                    {
                        printf("Matched %s!\n", functionName);
                        oldPointerValue = (void *)pThunk->u1.Function;
                        DWORD dwOldProtect;  // Correct type for VirtualProtect
                        if (!VirtualProtect(&pThunk->u1.Function, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &dwOldProtect))
                        {
                            printf("Failed to change memory protection for hooking\n");
                            return NULL;
                        }
                        pThunk->u1.Function = (ULONG_PTR)newFunctionPtr;
                        VirtualProtect(&pThunk->u1.Function, sizeof(LPVOID), dwOldProtect, &dwOldProtect);  // Correctly using DWORD
                        return oldPointerValue;
                    }
                }
                pThunk++;
                pOriginalThunk++;
            }
        }
        pImportDesc++;
    }
    return oldPointerValue;
}


HANDLE CustomCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    MessageBoxA(NULL, "No files for you", "You cannot open or create file due to poisoned restrictions", MB_OK);
    return NULL;
}

HANDLE CustomCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    MessageBoxA(NULL, "No files for you", "You cannot open or create file due to poisoned restrictions", MB_OK);
    return NULL;
}


void hook()
{
    printf("Will now hook\n");
    HookFunction("kernel32.dll", "CreateFileA", CustomCreateFileA);
    HookFunction("kernel32.dll", "CreateFileW", CustomCreateFileW);
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hook();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

