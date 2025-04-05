#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>

bool InjectDLL(const std::wstring& processName, const std::string& dllPath) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		std::cerr << "[-]Failed to create process snapshot!";
		return false;
	}
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe32)) {
		std::cerr << "[-]Failed to get first process!";
		CloseHandle(hSnapshot);
		return false;
	}

	DWORD processId = 0;
	do {
		if ((pe32.szExeFile) == processName) {
			processId = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapshot, &pe32));
	CloseHandle(hSnapshot);

	if (!processId)
	{
		std::cerr << "No javaw found!";
		return false;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!hProcess) {
		std::cerr << "Failed to open javaw process!w";
		return false;
	}

	LPVOID allocMemory = VirtualAllocEx(hProcess, nullptr, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!allocMemory)
			std::cerr << "Failed to alloc memory!";
		//CloseHandle(hProcess);
	
	if (!WriteProcessMemory(hProcess, allocMemory, dllPath.c_str(), dllPath.size() + 1, nullptr))
	{
		std::cerr << "Failed to write to memory!";
		VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
	{
		std::cerr << "Failed to get handle to kernel32.dll!";
		VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"), allocMemory, 0, nullptr);
	if (!hThread)
	{
		std::cerr << "Failed to create thread!";
		VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	std::cout << "INTLS INJECTED SUCCESFULLY!";
	return true;
}

int main() {
	std::wstring name = L"javaw.exe";
	std::string dll = "\\INTLS.dll";

	InjectDLL(name, dll);

	return 0;
}