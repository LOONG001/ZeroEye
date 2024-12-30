#include <map>
#include "EModule.hpp"


void DisplayHelp() {

    std::cout << "Usage: ZeroEye [options]" << std::endl;
    std::cout << "options:" << std::endl;
    std::cout << "  -h\t����" << std::endl;
    std::cout << "  -i\t<PE  ·��>\t#�г�Exe�ĵ����" << std::endl;
    std::cout << "  -p\t<�ļ�Ŀ¼>\t#�Զ������ļ�·���¿ɽٳ����õİ�����" << std::endl;
    std::cout << "  -s\t<ǩ��У��>\t#��������ǩ��exe����̽��" << std::endl;
    std::cout << "  -d\t<����ģ��>\t#����dllģ��" << std::endl;
    std::cout << "  -x\t<ָ���ܹ�>\t#ָ����Ҫ�ļܹ���86/64��,Ϊ����ɨ�����ּܹ�" << std::endl;
    std::cout << "  -g\t<�ų�����>\t#�ų�ָ��dll�ĳ���" << std::endl;
    std::cout << "  -IM\t<PE  ·��>\t#�鿴�����" << std::endl;
    std::cout << "  -EX\t<PE  ·��>\t#�鿴������" << std::endl;
    std::cout <<  std::endl;

    std::cout << "example:" << std::endl;
    std::cout << "  ZeroEye.exe -i a.exe\t\t\t\t\t#��ʾexe�����" << std::endl;
    std::cout << "  ZeroEye.exe -p c:\\\t\t\t\t\t#ɨ��c��������exe" << std::endl;
    std::cout << "  ZeroEye.exe -p c:\\ -s -x 64 -g \"api-ms|ucrtbase|crt\"\t#ɨ��c��������exe,���ҽ�ɨ��64λ������ǩ���ĳ���" << std::endl;
    std::cout << "  ZeroEye.exe -d a.dll\t\t\t\t\t#��ָ��dll����ģ��,����뵱ǰ·��" << std::endl;
    std::cout << "  ZeroEye.exe -IM/-EX a.exe/a.dll\t\t\t#�鿴�����/������" << std::endl;

}
int main(int argc, char* argv[]) {
    std::cout << R"(
  _____                        _____                
 |__  /   ___   _ __    ___   | ____|  _   _    ___ 
   / /   / _ \ | '__|  / _ \  |  _|   | | | |  / _ \
  / /_  |  __/ | |    | (_) | | |___  | |_| | |  __/
 /____|  \___| |_|     \___/  |_____|  \__, |  \___|
                                       |___/ Ver`3.4              

    Github:https://github.com/ImCoriander/ZeroEye
    ���ںţ�**�㹥��**
)" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    if (argc < 2) {
        DisplayHelp();
        return 1;
    }
    std::map<std::string, std::string> parsedArgs;

    bool isSign = false;
    int is64 = 0;
    std::vector<std::string> result;
    // ��������
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h") {
            DisplayHelp();
            return 0;
        }
        else if (arg == "-s") {
            isSign = true;
        }
        else if (arg == "-i" || arg == "-p" || arg == "-d" || arg == "-x" || arg == "-g" || arg == "-IM" || arg == "-EX" ) {
            if (i + 1 < argc) {
                parsedArgs[arg] = argv[++i];
            }
            else {
                std::cerr << "Missing value for option: " << arg << std::endl;
                DisplayHelp();
                return 1;
            }
        }
        else {
            std::cerr << "Unknown option: " << arg << std::endl;
            DisplayHelp();
            return 1;
        }
    }

    // ���ȹ���
    if (parsedArgs.find("-i") != parsedArgs.end()) {
        std::vector<std::string> DllList;
        bool is64Bit;
        std::filesystem::path filename = parsedArgs["-i"];

        ViewImportedDLLs(filename.string().c_str(), DllList, is64Bit, 0);
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "\t\t" << filename.stem().string() << " is " << (is64Bit ? "x64" : "x86") << "\n" << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        Exe_Output(filename, DllList);
    }

    if (parsedArgs.find("-x") != parsedArgs.end()) {
        std::string value = parsedArgs["-x"];
        if (value == "64") {
            is64 = 1;
        }
        else if (value == "86") {
            is64 = 2;
        }
        else {
            is64 = 0;
        }
    }
    if (parsedArgs.find("-g") != parsedArgs.end()) {
        std::string value = parsedArgs["-g"];
        result = SplitString(value, "|");
    }
    if (parsedArgs.find("-p") != parsedArgs.end()) {
        getFiles_and_view(parsedArgs["-p"].c_str(), is64, isSign, result);
    }

    if (parsedArgs.find("-d") != parsedArgs.end()) {
        std::string DemoFile = parsedArgs["-d"];
        std::string txtFile = ((std::filesystem::path)DemoFile).stem().string() + ".txt";

        EchoFunc(DemoFile, txtFile, true);
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "\n[+] Successful WriteTo : " << txtFile << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    if (parsedArgs.find("-IM") != parsedArgs.end()) {
        ListImportedFunctions(parsedArgs["-IM"].c_str());
    }

    if (parsedArgs.find("-EX") != parsedArgs.end()) {
        std::vector<std::string> Funclist;
        ListExportedFunctions(parsedArgs["-EX"].c_str(), false, Funclist);
    }

    // ��¼����ʱ��
    auto end = std::chrono::high_resolution_clock::now();

    // ��������ʱ��
    std::chrono::duration<double> duration = end - start;
    // ����ʱ��ת��Ϊ���Ӻ���
    int minutes = std::chrono::duration_cast<std::chrono::minutes>(duration).count();
    int seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count() % 60;

    // �������ʱ�䣨�����ʽ��
    std::cout << "\n[*] ��ʱ: " << minutes << "m " << seconds << "s" << std::endl;

    return 0;
}
