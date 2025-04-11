#include <Windows.h>
#include <TlHelp32.h>
#include <ShlObj.h>
#include <string>
#include <fstream>
#include <iostream>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t totalSize = size * nmemb;
    output->append((char*)contents, totalSize);
    return totalSize;
}

bool ReadJsonFromUrl(const std::string& url, json& j) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string readBuffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return false;

    try {
        j = json::parse(readBuffer);
        return true;
    }
    catch (...) {
        return false;
    }
}

bool DownloadToFile(const std::string& url, const std::string& filePath) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    FILE* file = nullptr;
    fopen_s(&file, filePath.c_str(), "wb");
    if (!file) {
        curl_easy_cleanup(curl);
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullptr);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(file);

    return res == CURLE_OK;
}

bool EnsureFolderExists(const std::string& folderPath) {
    std::wstring widePath(folderPath.begin(), folderPath.end());
    return SHCreateDirectoryExW(nullptr, widePath.c_str(), nullptr) == ERROR_SUCCESS || GetLastError() == ERROR_ALREADY_EXISTS;
}

bool InjectDLL(const std::wstring& processName, const std::string& dllPath) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to create process snapshot!\n";
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        std::cerr << "[-] Failed to get first process!\n";
        CloseHandle(hSnapshot);
        return false;
    }

    DWORD processId = 0;
    do {
        if (processName == pe32.szExeFile) {
            processId = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));
    CloseHandle(hSnapshot);

    if (!processId) {
        std::cerr << "[-] Process not found: javaw.exe\n";
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "[-] Failed to open target process!\n";
        return false;
    }

    LPVOID allocMemory = VirtualAllocEx(hProcess, nullptr, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocMemory) {
        std::cerr << "[-] Failed to allocate memory in target process!\n";
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, allocMemory, dllPath.c_str(), dllPath.size() + 1, nullptr)) {
        std::cerr << "[-] Failed to write to memory in target process!\n";
        VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        std::cerr << "[-] Failed to get handle to kernel32.dll!\n";
        VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"),
        allocMemory, 0, nullptr);

    if (!hThread) {
        std::cerr << "[-] Failed to create remote thread!\n";
        VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "[+] DLL injected successfully!\n";
    return true;
}

int main() {
    std::cerr << "[+]INTLS Bootstrapper v0.7\n";
    std::cerr << "          _____                    _____                _____                    _____            _____          \n";
    std::cerr << "         /\\    \\                  /\\    \\              /\\    \\                  /\\    \\          /\\    \\         \n";
    std::cerr << "        /::\\    \\                /::\\____\\            /::\\    \\                /::\\____\\        /::\\    \\        \n";
    std::cerr << "        \\:::\\    \\              /::::|   |            \\:::\\    \\              /:::/    /       /::::\\    \\       \n";
    std::cerr << "         \\:::\\    \\            /:::::|   |             \\:::\\    \\            /:::/    /       /::::::\\    \\      \n";
    std::cerr << "          \\:::\\    \\          /::::::|   |              \\:::\\    \\          /:::/    /       /:::/\\:::\\    \\     \n";
    std::cerr << "           \\:::\\    \\        /:::/|::|   |               \\:::\\    \\        /:::/    /       /:::/__\\:::\\    \\    \n";
    std::cerr << "           /::::\\    \\      /:::/ |::|   |               /::::\\    \\      /:::/    /        \\:::\\   \\:::\\    \\   \n";
    std::cerr << "  ____    /::::::\\    \\    /:::/  |::|   | _____        /::::::\\    \\    /:::/    /       ___\\:::\\   \\:::\\    \\  \n";
    std::cerr << " /\\   \\  /:::/\\:::\\    \\  /:::/   |::|   |/\\    \\      /:::/\\:::\\    \\  /:::/    /       /\\   \\:::\\   \\:::\\    \\ \n";
    std::cerr << "/::\\   \\/:::/  \\:::\\____\\/:: /    |::|   /::\\____\\    /:::/  \\:::\\____\\/:::/____/       /::\\   \\:::\\   \\:::\\____\\\n";
    std::cerr << "\\:::\\  /:::/    \\::/    /\\::/    /|::|  /:::/    /   /:::/    \\::/    /\\:::\\    \\       \\:::\\   \\:::\\   \\::/    /\n";
    std::cerr << " \\:::\\/:::/    / \\/____/  \\/____/ |::| /:::/    /   /:::/    / \\/____/  \\:::\\    \\       \\:::\\   \\:::\\   \\/____/ \n";
    std::cerr << "  \\::::::/    /                   |::|/:::/    /   /:::/    /            \\:::\\    \\       \\:::\\   \\:::\\    \\     \n";
    std::cerr << "   \\::::/____/                    |::::::/    /   /:::/    /              \\:::\\    \\       \\:::\\   \\:::\\____\\    \n";
    std::cerr << "    \\:::\\    \\                    |:::::/    /    \\::/    /                \\:::\\    \\       \\:::\\  /:::/    /    \n";
    std::cerr << "     \\:::\\    \\                   |::::/    /      \\/____/                  \\:::\\    \\       \\:::\\/:::/    /     \n";
    std::cerr << "      \\:::\\    \\                  /:::/    /                                 \\:::\\    \\       \\::::::/    /      \n";
    std::cerr << "       \\:::\\____\\                /:::/    /                                   \\:::\\____\\       \\::::/    /       \n";
    std::cerr << "        \\::/    /                \\::/    /                                     \\::/    /        \\::/    /        \n";
    std::cerr << "         \\/____/                  \\/____/                                       \\/____/          \\/____/         \n";
    std::cerr << "                                                                                                                  \n";
    const std::string versionURL = "https://raw.githubusercontent.com/1hyzh/intls_ver/refs/heads/main/version.json";
    const std::string localVersionPath = "C:\\INTLS\\local_version.json";
    const std::string folderPath = "C:\\INTLS\\";
    const std::string dllPath = "C:\\INTLS\\INTLS.dll";

    json remoteJson;
    if (!ReadJsonFromUrl(versionURL, remoteJson)) {
        std::cerr << "[-] Failed to fetch remote version info.\n";
        return 1;
    }

    double latestVersion = remoteJson.value("latestVersion", 0.0);
    std::string downloadURL = remoteJson.value("downloadURL", "");
	std::string changelog = remoteJson.value("changelog", "");

    // Log the remote version for debugging
    std::cout << "[*]Latest version: " << latestVersion << "\n";

    double currentVersion = 0.0;
    std::ifstream in(localVersionPath);
    if (in.is_open()) {
        try {
            json localJson;
            in >> localJson;
            currentVersion = localJson.value("latestVersion", 0.0);
        }
        catch (...) {}
        in.close();
    }

    // Log the local version for debugging
    std::cout << "[*] Local current version: " << currentVersion << "\n";

    bool dllExists = GetFileAttributesA(dllPath.c_str()) != INVALID_FILE_ATTRIBUTES;

    std::cout << "[i] Current Version: " << currentVersion << " | Latest Version: " << latestVersion << "\n";

    if (!dllExists || latestVersion > currentVersion) {
        std::cout << "[+] New version detected or DLL missing. Updating...\n";
        std::cout << "[i] Changelog:\n";
		std::cout << changelog << "\n";

        if (!EnsureFolderExists(folderPath)) {
            std::cerr << "[-] Failed to create folder: " << folderPath << " (Run as Admin)\n";
            return 1;
        }

        if (!DownloadToFile(downloadURL, dllPath)) {
            std::cerr << "[-] Failed to download DLL from: " << downloadURL << "\n";
            return 1;
        }

        // Log DLL file size
        DWORD fileSize = GetFileSize(CreateFileA(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL), NULL);
        std::cout << "[*] Downloaded DLL size: " << fileSize << " bytes\n";

        std::ofstream out(localVersionPath);
        out << json{ {"latestVersion", latestVersion} };
        out.close();

        std::cout << "[+] DLL downloaded and version updated.\n";
    }
    else {
        std::cout << "[=] DLL is up-to-date. No update needed.\n";
    }

    InjectDLL(L"javaw.exe", dllPath);
    std::cerr << "[i]Press [ENTER] to close this window!";
    while (!GetAsyncKeyState(VK_RETURN)) {
        Sleep(1);
    }
    return 0;
    
}
