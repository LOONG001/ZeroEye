#include <iostream>
#include <windows.h>
#include <vector>
#include <io.h>
#include <filesystem>
#include <fstream>
bool isx64 = false;
bool Is_SystemDLL(const char* dllName) {

    HMODULE hModule = LoadLibraryA(dllName);
    if (hModule)
    {
        FreeLibrary(hModule);
        return true;
    }
    return false;

}
void SetConsoleColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}
void Exe_Output(std::vector<std::string>& DllList) {
    if (DllList.size())
    {
        std::cout << "Imported DLLs:" << std::endl;
        for (const auto& dll : DllList) {
            if (!Is_SystemDLL(dll.c_str()))
            {
                SetConsoleColor(FOREGROUND_GREEN);
                std::cout << "[+] " << dll << std::endl;
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

            }
            else
            {
                std::cout << "   " << dll << std::endl;
            }

        }
    }
    else
    {

        SetConsoleColor(FOREGROUND_RED);
        std::cout << "[-] Not Find Imported" << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
} 
void File_Output(std::string filePath, std::vector<std::string>& DllList) {
    int iNum = 0;
    for (const auto& dll : DllList) {
        if (!Is_SystemDLL(dll.c_str()))
        {
            iNum += 1;
        }

    }
    if (!iNum)
    {
        std::cout << filePath << std::endl;
        return;
    }
    else
    {
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "[+] " << filePath << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    // 获取当前进程路径
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);
    std::filesystem::path currentDir = std::filesystem::path(currentPath).parent_path();
    std::filesystem::path targetDir;

    std::filesystem::path path(filePath);
    std::string ExeName = path.filename().string(); // 获取文件名
    if (isx64)
    {
        targetDir = currentDir / "x64bin" / ExeName;
    }
    else
    {
        targetDir = currentDir / "x86bin" / ExeName;
    }


    // 创建目标文件夹
    if (!std::filesystem::exists(targetDir)) {
        std::filesystem::create_directories(targetDir);
    }
    std::filesystem::copy_file(filePath, targetDir / ExeName, std::filesystem::copy_options::overwrite_existing);
    // 移动DLL文件并记录名称
    std::ofstream dllNamesFile(targetDir / "Infos.txt");
    dllNamesFile << filePath << std::endl;
    std::filesystem::path sourceDir = std::filesystem::path(filePath).parent_path();
    if (DllList.size())
    {
        for (const auto& dll : DllList) {
            std::filesystem::path sourceDllPath = sourceDir / dll;
            std::filesystem::path targetDllPath = targetDir / dll;
            if (!Is_SystemDLL(dll.c_str()))
            {
                dllNamesFile << "[+] " << dll << std::endl;
            }
            else
            {
                dllNamesFile << dll << std::endl;
            }

            if (std::filesystem::exists(sourceDllPath)) {
                std::filesystem::copy_file(sourceDllPath, targetDllPath, std::filesystem::copy_options::overwrite_existing);
            }
        }
    }


    dllNamesFile.close();
}
void ViewImportedDLLs(const char* filePath, std::vector<std::string>& DllList) {
    HMODULE hModule = LoadLibraryExA(filePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hModule == NULL) {
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        FreeLibrary(hModule);
        return;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        FreeLibrary(hModule);
        return;
    }

    DWORD importTableRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importTableRVA == 0) {

        FreeLibrary(hModule);
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<BYTE*>(hModule) + importTableRVA);
    while (importDescriptor->Name != NULL) {
        // 检查 importDescriptor 是否为有效指针
        if (IsBadReadPtr(importDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {

            break;
        }

        // 计算 DLL 名称的地址
        char* dllName = reinterpret_cast<char*>(reinterpret_cast<BYTE*>(hModule) + importDescriptor->Name);

        // 检查 dllName 的有效性
        if (dllName && !IsBadStringPtrA(dllName, MAX_PATH) && strlen(dllName) > 0) {
            DllList.push_back(dllName);  // 只有在 dllName 有效时才加入列表
        }

        importDescriptor++;

        // 终止条件，避免越界
        if (importDescriptor->Characteristics == NULL) {
            break;
        }
    }
    FreeLibrary(hModule);
    return;


}
bool hasReadPermission(const std::string& path) {
    struct _stat fileInfo;
    if (_stat(path.c_str(), &fileInfo) != 0) {
        if (errno == EACCES) {

            SetConsoleColor(FOREGROUND_RED);
            std::cerr << "[-] Permission denied: " << path << std::endl;
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        else {

            SetConsoleColor(FOREGROUND_RED);
            std::cerr << "[-] Unable to access path: " << path << " (Error code: " << errno << ")" << std::endl;
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }
        return false;
    }
    return true;
}
void getFiles_and_view(const std::string& path) {
    if (!hasReadPermission(path)) {
        return;  // 如果没有访问权限，直接返回
    }

    intptr_t hFile = 0;
    struct _finddata_t fileinfo;

    std::string searchPath = path + "\\*";

    if ((hFile = _findfirst(searchPath.c_str(), &fileinfo)) == -1) {
        std::cerr << "[-] Failed to open directory: " << path << std::endl;
        return;
    }

    do {
        if (fileinfo.attrib & _A_SUBDIR) {
            // 过滤掉 "." 和 ".." 目录
            if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
                // 排除隐藏的系统目录，例如 "$Recycle.Bin"
                if (fileinfo.name[0] != '$') {
                    std::string subdirPath = path + "\\" + fileinfo.name;
                    getFiles_and_view(subdirPath);
                }
            }
        }
        else {
            std::string fullPath = path + "\\" + fileinfo.name;

            if (fullPath.size() > 4 && fullPath.substr(fullPath.size() - 4) == ".exe") {
                try {
                    std::vector<std::string> DllList;
                    ViewImportedDLLs(fullPath.c_str(), DllList);
                    File_Output(fullPath.c_str(), DllList);
                }
                catch (const std::exception& e) {
                    SetConsoleColor(FOREGROUND_RED);
                    std::cerr << "[-] Exception while processing file: " << fullPath << ". Error: " << e.what() << std::endl;
                    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

                }
                catch (...) {
                    SetConsoleColor(FOREGROUND_RED);
                    std::cerr << "[-] Unknown error occurred while processing file: " << fullPath << std::endl;
                    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

                }
            }
        }
    } while (_findnext(hFile, &fileinfo) == 0);

    _findclose(hFile);
}
void DisplayHelp() {

    std::cout << "Usage: ZeroEye [options]" << std::endl;
    std::cout << "选项:" << std::endl;
    std::cout << "  -h\t帮助" << std::endl;
    std::cout << "  -i\t<Exe 路径>\t列出Exe的导入表" << std::endl;
    std::cout << "  -p\t<文件路径>\t自动搜索文件路径下可劫持利用的白名单" << std::endl;
}
int main(int argc, char* argv[]) {



    std::cout << R"(
  _____                        _____                
 |__  /   ___   _ __    ___   | ____|  _   _    ___ 
   / /   / _ \ | '__|  / _ \  |  _|   | | | |  / _ \
  / /_  |  __/ | |    | (_) | | |___  | |_| | |  __/
 /____|  \___| |_|     \___/  |_____|  \__, |  \___|
                                       |___/                 
)" << std::endl;
#if defined(_WIN64)
    isx64 = true;
#else
    isx64 = false;
#endif
    std::cout << (isx64 ? "\t\t\t\t  x64" : "\t\t\t\t  x86") << " Version:3.1\n" << std::endl;

    if (argc < 2) {
        DisplayHelp();
        return 1;
    }


    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0) {
            DisplayHelp();
            return 0;
        }
        else if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {

                std::vector<std::string> DllList;
                ViewImportedDLLs(argv[++i], DllList);
                Exe_Output(DllList);
            }
        }
        else if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                getFiles_and_view(argv[++i]);
            }
        }

        else {
            std::cerr << "Unknown option: " << argv[i] << std::endl;
            DisplayHelp();
            return 1;
        }
    }


    return 0;
}
