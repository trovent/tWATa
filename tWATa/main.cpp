#include "token.h"

int main(int argc, char* argv[])
{
	int pid = 0;
	if (argc == 2)
	{
		pid = std::atoi(argv[1]);
	}

	HANDLE hTokenDup = NULL;
	if (pid != 0)
	{
		hTokenDup = stealingToken(pid);
	}
	else 
	{
		enumerateProcesses();
	}

	return 0;
}