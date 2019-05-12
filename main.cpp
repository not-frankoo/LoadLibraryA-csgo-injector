#include "MemManager.h"

int main() {

	MemManager Mem("csgo.exe");

	std::getchar();
	return 0;
}




/*bool Injectdll(HANDLE hprocess, const char * dllpath) {

	void* dllpathInTargetMemory = VirtualAllocEx(hprocess, NULL, strlen(dllpath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!dllpathInTargetMemory) {
		std::cout << "couldn't allocate memory" << std::endl;
		std::getchar();
		return false;
	}
	else
	{
		// should print out the address of that memory location.
		std::cout << "[+] allocated memory at : " << &dllpathInTargetMemory << std::endl;
	}

	if (!WriteProcessMemory(hprocess, dllpathInTargetMemory,dllpath, strlen(dllpath), NULL)) {
		std::cout << "failed to write dll into target process!" << std::endl;
		std::getchar();
		return false;
	}
	else
	{
		std::cout << "[+] Wrote dll into Target Process" << std::endl;
	}


	void* LoadlibraryAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (!LoadlibraryAddr) {
		std::cout << "couldn't get LoadlibraryAddr address." << std::endl;
		std::getchar();
		return false;
	}
	else
	{
		std::cout << "[+] LoadlibraryAddr :" << &LoadlibraryAddr << std::endl;
	}


	HANDLE remoteThread = CreateRemoteThread(hprocess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadlibraryAddr, dllpathInTargetMemory, NULL, NULL);
	if (remoteThread == NULL)
	{
		std::cout << "remotethread failed!" << std::endl;
		std::getchar();
		return false;
	}
	else
	{
		std::cout << "[+] Created a remote Thread!" << std::endl;
		std::cout << "[+]Remote Thread Handle :" << &remoteThread << std::endl;
	}
	CloseHandle(hprocess);
	return true;
}*/