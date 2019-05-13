#include "MemManager.h"

// #define DEBUG

std::uint32_t MemManager::GetProcessID(std::string_view process_name) const noexcept {
	PROCESSENTRY32 processentry;
	const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

	if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
		return 0;

	processentry.dwSize = sizeof(MODULEENTRY32);

	while (Process32Next(snapshot_handle.get(), &processentry) == TRUE) {
		if (process_name.compare(processentry.szExeFile) == 0)
			return processentry.th32ProcessID;
	}
	return 0;
}


MemManager::MemManager(std::string_view process_name) noexcept {
	const std::uint32_t process_id = this->GetProcessID(process_name);
	this->m_processHandle = OpenProcessHandle(process_id);
	injectdll(this->m_processHandle.get(), "C:\\Test.dll");
#ifdef DEBUG
	std::cout << "Process ID : " << process_id << std::endl;
	std::cout << "Handle opened : " << std::hex << this->m_processHandle << std::endl;
#endif // DEBUG
	std::cout << "Dll injected!" << std::endl;
}

bool MemManager::injectdll(HANDLE hprocess, const char * dllpath) {
	void* dllpathInTargetMemory = VirtualAllocEx(hprocess, NULL, strlen(dllpath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!dllpathInTargetMemory) {
    #ifdef DEBUG
		std::cout << "couldn't allocate memory" << std::endl;
		std::getchar();
    #endif // DEBUG
	return false;
	}
	else
	{
    #ifdef DEBUG
		std::cout << "[+] allocated memory at : 0x" << std::hex << dllpathInTargetMemory << std::endl;
    #endif // DEBUG
	}

	if (!WriteProcessMemory(hprocess, dllpathInTargetMemory, dllpath, strlen(dllpath), NULL)) {
    #ifdef DEBUG
		std::cout << "failed to write dll into target process!" << std::endl;
		std::getchar();
    #endif // DEBUG
	return false;
	}
	else
	{
    #ifdef DEBUG
		std::cout << "[+] Wrote dll into Target Process" << std::endl;
    #endif // DEBUG
	}


	void* LoadlibraryAddr = (void*)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (!LoadlibraryAddr) {
    #ifdef DEBUG
		std::cout << "couldn't get LoadlibraryAddr address." << std::endl;
		std::getchar();
    #endif // DEBUG
	return false;
	}
	else
	{
    #ifdef DEBUG
		std::cout << "[+] LoadlibraryAddr : 0x" << std::hex << LoadlibraryAddr << std::endl;
    #endif // DEBUG
	}

	HANDLE remoteThread = CreateRemoteThread(hprocess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadlibraryAddr, dllpathInTargetMemory, NULL, NULL);
	if (remoteThread == NULL)
	{
    #ifdef DEBUG
		std::cout << "remotethread failed !" << std::endl;
		std::getchar();
    #endif // DEBUG
	return false;
	}
	else
	{
    #ifdef DEBUG
		std::cout << "[+] Created a remote Thread!" << std::endl;
		std::cout << "[+]Remote Thread Handle : 0x" << std::hex << remoteThread << std::endl;
    #endif // DEBUG
	}

	// CloseHandle(hprocess); this should be closed by our smart pointer after our program exit and object is destroyed?
	return true;
}

MemManager::~MemManager() {

}

