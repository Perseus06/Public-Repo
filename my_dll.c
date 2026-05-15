/* 
Name:
dllmain.c - the DLL to inject to other process.

to compile with gcc (two prompts one by another):
gcc -c -o my_dll.o my_dll.c
gcc -s -shared -o my_dll.dll my_dll.o -Wl,--subsystem,windows

Description:
File that contains the code for a simple DLL (dynamic linked library for windows OS.
When this DLL will be loaded by a process, a message box will pop on the screen.
When process loads a DLL it is considered DLL_PROCESS_ATTACH, and therefore all the code that is under that section will be runned by any process that load this DLL.
*/

#include <windows.h>

// this function contains all the code that will be runned by every process that loads this DLL.
// in this case, a message box will pop up.
void DLLCode()
{
    MessageBoxA(NULL, TEXT("Hello there!"), TEXT("creative title name"), MB_OK);
}

// the entry point for the DLL.
// when a process loads this DLL, the DLL will start to run the code from this point.
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DLLCode();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

