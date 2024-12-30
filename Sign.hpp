#include <Windows.h>
#include <wintrust.h>
#include <iostream>
#pragma comment(lib, "Wintrust.lib")


const GUID WINTRUST_ACTION_GENERIC_VERIFY_V2 =
{ 0xaac56b, 0xcd44, 0x11d0, { 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } };
// 用于宽字符串到窄字符串的转换
std::wstring charToWChar(const char* str) {
    int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    std::wstring wstr(len, 0);
    MultiByteToWideChar(CP_ACP, 0, str, -1, &wstr[0], len);
    return wstr;
}

bool IsFileSigned(const char* filePath) {
    // 将 char* 转换为 wchar_t*
    std::wstring wFilePath = charToWChar(filePath);

    // 定义 WINTRUST_FILE_INFO 结构
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wFilePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    // 定义 WINTRUST_DATA 结构
    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(trustData);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwUIContext = 0;
    trustData.pFile = &fileInfo;

    // 使用 Authenticode 策略标识符
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // 调用 WinVerifyTrust
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    // 释放状态
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    // 检查返回状态
    return status == ERROR_SUCCESS;
}

