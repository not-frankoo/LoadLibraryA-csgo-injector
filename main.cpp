#include <iostream>
#include <windows.h>
#include <tlhelp32.h>


bool Injectdll(HANDLE hprocess,const char * dllpath);
HANDLE GetProcessHandle(const char* ProcName);
int main() {
	HANDLE hprocess = GetProcessHandle("csgo.exe");
	if (hprocess != NULL) {
		printf("[+] obtained handle from csgo!\n");
		bool injected = Injectdll(hprocess, "C:\\Test.dll");
		if (injected) {
			printf("[+] Dll injected !\n");
			std::getchar();
		}
		else
		{
			printf("[-] failed to inject Dll\n");
			std::getchar();
		}
	}

	std::getchar();
	return 0;
}


HANDLE GetProcessHandle(const char* ProcName) {

	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot failed! \n");
		std::getchar();
		CloseHandle(hProcessSnap);
		return NULL;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)) {
		printf("Process32First failed!\n");
		std::getchar();
		CloseHandle(hProcessSnap);
		return NULL;
	}
	do
	{
		// printf("[+]  process : %s \n", pe32.szExeFile);
		if (strcmp(pe32.szExeFile, ProcName) == 0) {
			printf("[+]found csgo process !\n");
			hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, pe32.th32ProcessID);
			if (hProcess != NULL) {
				return hProcess;
			}
			else
			{
				printf("[---] Failed to open process %s.\n", pe32.szExeFile);
				std::getchar();
				return NULL;
			}
				
		}

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return NULL;
}

bool Injectdll(HANDLE hprocess, const char * dllpath) {

	void* dllpathInTargetMemory = VirtualAllocEx(hprocess, NULL, strlen(dllpath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!dllpathInTargetMemory) {
		printf("couldn't allocate memory \n");
		std::getchar();
		return false;
	}
	else
	{
		printf("[+] allocated memory at : 0x%p \n", dllpathInTargetMemory);
	}

	if (!WriteProcessMemory(hprocess, dllpathInTargetMemory,dllpath, strlen(dllpath), NULL)) {
		printf("failed to write dll into target process!\n");
		std::getchar();
		return false;
	}
	else
	{
		printf("[+] Wrote dll into Target Process \n");
	}


	void* LoadlibraryAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (!LoadlibraryAddr) {
		printf("couldn't get LoadlibraryAddr address.\n");
		std::getchar();
		return false;
	}
	else
	{
		printf("[+] LoadlibraryAddr : 0x%p\n", LoadlibraryAddr);
	}


	HANDLE remoteThread = CreateRemoteThread(hprocess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadlibraryAddr, dllpathInTargetMemory, NULL, NULL);
	if (remoteThread == NULL)
	{
		printf("remotethread failed !\n");
		std::getchar();
		return false;
	}
	else
	{
		printf("[+] Created a remote Thread!\n");
		printf("[+]Remote Thread Handle : %p\n", remoteThread);
	}
	CloseHandle(hprocess);
	return true;
}