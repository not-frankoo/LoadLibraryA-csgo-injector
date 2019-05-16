#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <memory>
#include <string_view>



#ifndef MemManager_H
#define MemManager_H

    void Inject(std::string_view process_name);
	std::uint32_t GetProcessID(std::string_view process_name);
	bool injectdll(HANDLE hprocess, std::string_view dllpath);

	struct HandleDisposer
	{
		using pointer = HANDLE;
		void operator()(HANDLE handle) const
		{
			if (handle != NULL || handle != INVALID_HANDLE_VALUE)
			{
				CloseHandle(handle);
			}
		}
	};
    static std::unique_ptr<HANDLE, HandleDisposer> m_processHandle;

	using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

	static unique_handle OpenProcessHandle(const std::uint32_t process_id)
	{
		if (process_id == 0)
			return nullptr;

		unique_handle processhandle(OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, false, process_id));

		if (processhandle.get() == nullptr)
			return nullptr;
		
		return processhandle;
	}


#endif 