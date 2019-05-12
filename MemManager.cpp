#include "MemManager.h"

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

	std::cout << "Process ID : " << process_id << std::endl;
	std::cout << "Handle opened : " << std::hex << this->m_processHandle << std::endl;
}

MemManager::~MemManager() {

}

