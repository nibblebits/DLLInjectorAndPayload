#include <windows.h>
#include <stdio.h>

BOOL InjectDLL(DWORD dwProcessId, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
    if (hProcess == NULL) {
        printf("Error: the specified process couldn't be opened.\n");
        return FALSE;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteMemory == NULL) {
        printf("Error: the memory could not be allocated inside the chosen process.\n");
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteMemory, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
        printf("Error: there was an issue writing the DLL path to the target process's memory.\n");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create a remote thread that calls LoadLibrary
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA"), pRemoteMemory, 0, NULL);
    if (hThread == NULL) {
        printf("Error: the remote thread could not be created.\n");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Wait for the remote thread to terminate
    WaitForSingleObject(hThread, INFINITE);

    // Free the allocated memory and close handles
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("DLL successfully injected\n");
    return TRUE;
}

int main(int argc, const char** argv) {
    if (argc < 3)
    {
        printf("EXPECTED: <processId> <FilepathToDllToInject>\n");
        return -1;
    }
    DWORD dwProcessId = (DWORD) atol(argv[1]);
    
    const char* dllPath = argv[2];

    if (InjectDLL(dwProcessId, dllPath)) {
        printf("Injection successful.\n");
    } else {
        printf("Injection failed.\n");
    }

    return 0;
}
