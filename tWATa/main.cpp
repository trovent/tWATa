#include "token.h"
#include <unordered_map>
#include <list>
#include <string>

void enumerateProcessess();

struct TOKEN_INFORMATION
{
	HANDLE hToken;
	INT pid;
	TUSER tokenUserInformation;
	TSTAT tokenStatistics;
	TINTG tokenIntegrityLevel;
	TELEV tokenElevationType;
};

int main(int argc, char* argv[])
{
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

	std::unordered_map<std::wstring, std::list<TOKEN_INFORMATION>> user_token {};

	HANDLE hProcess;
	HANDLE hToken;
	do
	{
		TOKEN_INFORMATION tInfo = {};
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pe32.th32ProcessID);
		if (hProcess)
		{
			if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
			{
				tInfo.hToken = hToken;
				tInfo.pid = pe32.th32ProcessID;
				tInfo.tokenUserInformation = getTokenUser(hToken);
				tInfo.tokenStatistics = getTokenStatistics(hToken);
				tInfo.tokenIntegrityLevel = getTokenIntegrityLevel(hToken);
				tInfo.tokenElevationType = getTokenElevationType(hToken);

				wchar_t* user;
				user = wcscat(tInfo.tokenUserInformation.lpDomain, L"\\");
				user = wcscat(user, tInfo.tokenUserInformation.lpName);
				std::wstring wuser(user);

				if (!user_token.count(wuser))
				{
					user_token[wuser] = {};
				}
				std::list tokens = user_token[wuser];
				tokens.insert(tokens.end(), tInfo);
				user_token[wuser] = tokens;
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);

	int i = 0;
	wprintf(L"Available tokens for impersonation: \n");
	for (const auto& kv : user_token)
	{
		i++;
		wprintf(L"[%d] %s\n", i, kv.first.c_str());
		std::list<TOKEN_INFORMATION> tokens = kv.second;
		for (TOKEN_INFORMATION token : tokens)
		{
			wprintf(L"\t[%d] TokenType: %s\tImpersonationLevel: %s\tisElevated: %s\tElevationType: %s\tIntegrityLevel: %s\n", 
				token.pid, token.tokenStatistics.tokenType, token.tokenStatistics.impersonationLevel, token.tokenElevationType.isElevated, token.tokenElevationType.elevationType, token.tokenIntegrityLevel.integrityLevel);
		}
	}
	//stealToken(hToken);

	return 0;
}