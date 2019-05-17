#include "MemManager.h"


std::uint32_t GetProcessID(std::string_view process_name)  {
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


void Inject(std::string_view process_name) {
	const std::uint32_t process_id = GetProcessID(process_name);
	m_processHandle = OpenProcessHandle(process_id);
	injectdll(m_processHandle.get(), "C:\\Voxy.dll");
}

bool injectdll(HANDLE hprocess, std::string_view dllpath) {

	void* dllpathInTargetMemory = VirtualAllocEx(hprocess, NULL, dllpath.length(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	if (!dllpathInTargetMemory)
		return false;


	if (!WriteProcessMemory(hprocess, dllpathInTargetMemory, dllpath.data(), dllpath.length(), NULL))
		return false;
	
	
	void* LoadlibraryAddr = reinterpret_cast<void*>(GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"));

	if (!LoadlibraryAddr)
		return false;


	HANDLE remoteThread = CreateRemoteThread(hprocess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadlibraryAddr, dllpathInTargetMemory, NULL, NULL);
	if (remoteThread == NULL)
		return false;

	return true;
}


