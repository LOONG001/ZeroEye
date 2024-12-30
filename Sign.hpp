#include <Windows.h>
#include <wintrust.h>
#include <iostream>
#pragma comment(lib, "Wintrust.lib")


const GUID WINTRUST_ACTION_GENERIC_VERIFY_V2 =
{ 0xaac56b, 0xcd44, 0x11d0, { 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } };
// ���ڿ��ַ�����խ�ַ�����ת��
std::wstring charToWChar(const char* str) {
    int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    std::wstring wstr(len, 0);
    MultiByteToWideChar(CP_ACP, 0, str, -1, &wstr[0], len);
    return wstr;
}

bool IsFileSigned(const char* filePath) {
    // �� char* ת��Ϊ wchar_t*
    std::wstring wFilePath = charToWChar(filePath);

    // ���� WINTRUST_FILE_INFO �ṹ
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = wFilePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    // ���� WINTRUST_DATA �ṹ
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

    // ʹ�� Authenticode ���Ա�ʶ��
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // ���� WinVerifyTrust
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    // �ͷ�״̬
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    // ��鷵��״̬
    return status == ERROR_SUCCESS;
}

