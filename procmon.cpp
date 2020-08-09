// ProcMon.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include<cstring>
#include <locale.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<iostream>
#include<string.h>
#include<windows.h>
#include<tlhelp32.h>
#include<io.h>
#include <assert.h>
//#include "pch.h"
#include<stdio.h>
#include <algorithm>
#include <vector>

using namespace std;

struct Logfile
{
	char ProcessName[100];
	unsigned int pid;
	unsigned int ppid;
	unsigned int thread_cnt;
};

class ThreadInfo
{
private:
	DWORD PID;          //DWORD = short double data type
	HANDLE hThreadSnap; //
	THREADENTRY32 te32; //structure defined in windows.h
public:
	ThreadInfo(DWORD);
	BOOL ThreadsDisplay();
};


ThreadInfo::ThreadInfo(DWORD no)
{
	PID = no;

	/////////header/////////////
	//name  : CreateToolhelp32Snapshot
	//input :
	//      1.dwFlags :- this parameter used for which portion of the system needs to be included in snapshot.
    //      2.th32ProcessID :- Process Identifier of the process to be included in snapshot.(this parameter used only for certain dwflags)
	//return:Handle
	//use   :used to take snapshot of specified/all  process/heaps/modules/threads.
	///////////////////////////

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, PID);

	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
		std::cout << "Unable to create the snapshot of the current thread pool\n";
		return;
	}

	te32.dwSize = sizeof(THREADENTRY32);    //dwsize should be initialized for Thread32first to work
}

BOOL ThreadInfo::ThreadsDisplay()
{
    /////////header/////////////
	//name  : Thread32First
	//input :
	//      1.HANDLE :- Give handle to the snapshot which is returned from previous call to CreateToolhelp32Snapshot().
    //      2.LPTHREADENTRY32 :- A pointer to a threadentry32 structure.
	//return:BOOL(TRUE if first entry of the thread list has been copied to the buffer)
	//use   :Retrieves information about the first thread encountered in system snapshot.
	///////////////////////////


	if (!Thread32First(hThreadSnap, &te32))
	{
		std::cout << "Error : In getting the first Thread\n";
		CloseHandle(hThreadSnap);
		return(FALSE);
	}

	std::cout << "Thread of this process :" << "\n";

	do
	{
		if (te32.th32OwnerProcessID == PID)
		{
			std::cout << "\t Thread ID:" << te32.th32ThreadID << "\n";
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return(TRUE);

}


class DLLInfo
{
private:
	DWORD PID;
	MODULEENTRY32 me32;
	HANDLE hProcessSnap;
public:
	DLLInfo(DWORD);
	BOOL DependentDLLDisplay();
};

DLLInfo::DLLInfo(DWORD no)
{
	PID = no;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		std::cout << "Error: Unable to create the snap shot of the current thread pool\n";
		return;
	}
	me32.dwSize = sizeof(MODULEENTRY32);
}

BOOL DLLInfo::DependentDLLDisplay()
{
	char arr[200];

	if (!Module32First(hProcessSnap, &me32))
	{
		std::cout << "Failed to get DLL Info\n";
		CloseHandle(hProcessSnap);
		return(FALSE);
	}

	std::cout << "Dependent DLL of this process\n";

	do
	{
		//wcstombs_s(NULL, arr, 200, me32.szModule, 200);

		std::cout << arr << "\n";
	} while (Module32Next(hProcessSnap, &me32));

	CloseHandle(hProcessSnap);
	return(TRUE);

}


class ProcessInfo
{
private:
	DWORD PID;
	DLLInfo*pdobj;
	ThreadInfo*ptobj;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
public:
	ProcessInfo();
	BOOL ProcessDisplay(const char*);
	BOOL ProcessLog();
	BOOL ReadLog(DWORD, DWORD, DWORD, DWORD);
	BOOL ProcessSearch(char*);
	BOOL KillProcess(char*);
};

ProcessInfo::ProcessInfo()
{
	pdobj = NULL;
	ptobj = NULL;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		std::cout << "Error:Unable to create the nap shot  of the running process\n";
		return;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
}

BOOL ProcessInfo::ProcessLog()
{
	// String month[]= {"JAN","FEB","MAR","APR","MAY","JUNE","JULY","AUG","SEPT","OCT","NOV","DEC"};
	//char month[][] = {'JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEPT','OCT','NOV','DEC'};
	char FileName[50], arr[512];

	int ret = 0, fd = 0, count = 0;
	SYSTEMTIME lt;
	Logfile fobj;
	FILE *fp;
	GetLocalTime(&lt);

	// sprintf_s(FileName, "C://MarvellousLog %02d_%02d_%02d%s.txt",lt.wHour,lt.wMinute,lt.wDay,month[lt.wMonth-1]);

	fp = fopen(FileName, "wb");
	if (fp == NULL)
	{
		std::cout << "Unable to create log file\n";
		return FALSE;
	}

	else
	{
		std::cout << "Log file succesfully gets created as : " << FileName<<"\n";
		// std::cout << "Time of log file creation is->"<<lt.wHour<<":"<<lt.wMinute<<" : "<<lt.wDay<<"th "<<month[lt.wMonth - 1] << "\n";
	}

	if (!Process32First(hProcessSnap, &pe32))
	{
		std::cout << "Error: In finding the first process." << "\n";
		CloseHandle(hProcessSnap);
		return(FALSE);
	}

	do
	{
		//wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
		cout<<"in"<<"\n";
		strcpy(fobj.ProcessName, arr);
		fobj.pid = pe32.th32ProcessID;
		fobj.ppid = pe32.th32ParentProcessID;
		fobj.thread_cnt = pe32.cntThreads;
		fwrite(&fobj, sizeof(fobj), 1, fp);
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	fclose(fp);

	return(TRUE);
}

BOOL ProcessInfo::ProcessDisplay(const char*option)
{
	char arr[200];

	if (!Process32First(hProcessSnap, &pe32))
	{
		std::cout << "Error: Unable to read the first Process\n";
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		std::cout << "------------------------------------------------------------\n";

		//wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
		cout<<"in"<<"\n";
		std::cout << "PROCESS NAME: " << arr<<"\n";
		std::cout <<" PID: "<<pe32.th32ProcessID << "\n";
		std::cout <<"Parent PID: "<< pe32.th32ParentProcessID<<"\n";
		std::cout<< "No of Threads: " << pe32.cntThreads<<"\n";

		if ((strcmp(option, "-a") == 0) || (strcmp(option, "-d") == 0) || (strcmp(option, "-t") == 0))
		{
			if ((strcmp(option, "-t") == 0) || (strcmp(option, "-a") == 0))
			{
				ptobj = new ThreadInfo(pe32.th32ProcessID);
				ptobj->ThreadsDisplay();
				delete ptobj;
			}

			if ((strcmp(option, "-d") == 0) || (strcmp(option, "-a") == 0))
			{
				pdobj = new DLLInfo(pe32.th32ProcessID);
				pdobj->DependentDLLDisplay();
				delete pdobj;
			}

		}
		std::cout<< "------------------------------------------------------------\n";

	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return TRUE;
}


BOOL ProcessInfo::ReadLog(DWORD hr, DWORD min, DWORD date, DWORD month)
{
	char FileName[50];
	// String montharr[] = { 'JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEPT','OCT','NOV','DEC' };
	int ret = 0, count = 0;
	Logfile fobj;
	FILE *fp;
	// sprintf_s(FileName, "C://MarvellousLog %02d_%02d_%02d%s.txt",hr,min,date,montharr[month-1]);

	fp = fopen(FileName, "rb");

	if (fp == NULL)
	{
		std::cout << "Error : Unable to open log file named as :" << FileName << "\n";
		return FALSE;
	}

	while ((ret = fread(&fobj, 1, sizeof(fobj), fp)) != 0)
	{
		 std::cout << "--------------------------------------------------------------" << "\n";
		 std::cout << "Process Name :" << fobj.ProcessName << "\n";
		 std::cout << "PID of current process :" << fobj.pid << "\n";
		 std::cout << "Parent process PID :" << fobj.ppid << "\n";
		 std::cout << "Thread count of process :" << fobj.thread_cnt << "\n";
	}

	return TRUE;
}

BOOL ProcessInfo::ProcessSearch(char*name)
{
	char arr[200];
	BOOL flag = FALSE;
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		//wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);

		if (strcmp(arr, name) == 0)
		{
			std::cout <<"PROCESS NAME: " << arr<<"\n";
			std::cout <<"PID:" << pe32.th32ProcessID<<"\n";
			std::cout <<"Parent PID: " << pe32.th32ParentProcessID<<"\n";
			std::cout << "No of Thread: " << pe32.cntThreads<<"\n";
			flag = TRUE;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	return flag;
}

BOOL ProcessInfo::KillProcess(char*name)
{
	char arr[200];
	int pid = -1;
	BOOL bret;
	HANDLE hprocess;

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		//wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200);
		if (strcmp(arr, name) == 0)
		{
			pid = pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	if (pid == -1)
	{
		std::cout << "ERROR : There is no such process" << "\n";
		return(FALSE);
	}

	hprocess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (hprocess == NULL)
	{
		std::cout << "ERROR : There is no access to terminate" << "\n";
		return(FALSE);
	}

	bret = TerminateProcess(hprocess, 0);
	if (bret == FALSE)
	{
		std::cout << "ERROR : Unable to terminate process"<<"\n";
		return FALSE;
	}
	return true;
}


BOOL HardwareInfo()
{
	SYSTEM_INFO siSysInfo;
	GetSystemInfo(&siSysInfo);

	std::cout << "OEM ID: " << siSysInfo.dwOemId <<"\n";
	std::cout << "Number of processors:" << siSysInfo.dwNumberOfProcessors << "\n";
	std::cout << "Page size: " << siSysInfo.dwPageSize << "\n";
	std::cout << "Processor type: " << siSysInfo.dwProcessorType <<"\n";
	std::cout << "Minimum application address:" << siSysInfo.lpMinimumApplicationAddress << "\n";
	std::cout << "Maximum application address:"<<siSysInfo.lpMaximumApplicationAddress<<"\n";
	std::cout << "Active processor mask: “<<siSysInfo.dwActiveProcessorMask"<<"\n";

	return(TRUE);
}



void DisplayHelp()
{
	std::cout << "ps : Display all information of process" << "\n";
	std::cout << "ps -t : Display all information about threads" << "\n";
	std::cout << "ps -d :Display all information about DLL" << "\n";
    std::cout << "cls : Clear the contents on console" << "\n";
    std::cout << "log : Creates log of current running process on C drive" << "\n";
	std::cout << "readlog : Display the information from specified log file" << "\n";
	std::cout << "sysinfo : Display the current hardware configuration" << "\n";
	std::cout << "search : Search and display information of specific running process"<<"\n";
	std::cout << "kill process_name : Kill the mentioned process"<< "\n";
    std::cout << "exit : Terminate ProcMon" << "\n";
}


int main(int argc, char* argv[])
{
	BOOL bret;
	char *ptr = NULL;
	ProcessInfo *ppobj = NULL;
	char command[4][80], str[80];
	int count, min, date, month, hr;
	const char*arr[] = { "-a","-t","-d" };

	while (1)
	{
		fflush(stdin);
		strcpy(str, "");

		std::cout << "\n" << "ProcMon : > ";
		fgets(str, 80, stdin);

		count = sscanf(str, "%s %s %s %s", command[0], command[1], command[2], command[3]);

		if (count == 1)
		{
			if (strcmp(command[0], "ps") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessDisplay(arr[0]);
				if (bret == FALSE)
					std::cout << "ERROR : Unable to display process" << "\n";
				delete ppobj;
			}



			else if (strcmp(command[0], "log") == 0)
			{

				ppobj = new ProcessInfo();
				bret = ppobj->ProcessLog();

				if (bret == FALSE)
					std::cout << "ERROR : Unable to create log file" << "\n";

				delete ppobj;
			}


			else if (strcmp(command[0], "sysinfo") == 0)
			{
				bret = HardwareInfo();
				if (bret == FALSE)
					std::cout << "ERROR : Unable to get hardware information" << "\n";

				std::cout << "Hardware information of current system is :" << "\n";

			}


			else if (strcmp(command[0], "readlog") == 0)
			{
				ProcessInfo *ppobj;
				ppobj = new ProcessInfo();

				std::cout << "Enter log file details as :" << "\n";

				std::cout << "Hour : ";
				std::cin >> hr;
				std::cout << "\n" << "Minute : ";
				std::cin >> min;
				std::cout << "\n" << "Date : ";
				std::cin >> date;
				std::cout << "\n" << "Month : ";
				std::cin >> month;

				bret = ppobj->ReadLog(hr, min, date, month);

				if (bret == FALSE)
					std::cout << "ERROR : Unable to read specified log file" << "\n";
				delete ppobj;
			}


			else if (strcmp(command[0], "clear") == 0)
			{
				system("cls");
				continue;
			}

			else if (strcmp(command[0], "help") == 0)
			{
				DisplayHelp();
				continue;
			}

			else if (strcmp(command[0], "exit") == 0)
			{
				std::cout << "\n" << "Terminating the Marvellous ProcMon" << "\n";
				break;
			}

			else
			{
				std::cout << "\n" << "ERROR : Command not found !!" << "\n";
				continue;
			}


		}

		else if (count == 2)
		{
			if (strcmp(command[0], "ps") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessDisplay(command[1]);

				if (bret == FALSE)
					std::cout << "ERROR :Unable to display process information" << "\n";

				delete ppobj;
			}

			else if (strcmp(command[0], "search") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->ProcessSearch(command[1]);
				if (bret == FALSE)
					std::cout << "ERROR : There is no such process" << "\n";
				delete ppobj;

				continue;
			}

			else if (strcmp(command[0], "kill") == 0)
			{
				ppobj = new ProcessInfo();
				bret = ppobj->KillProcess(command[1]);

				if (bret == FALSE)
					std::cout << "ERROR : There is no such process" << "\n";
				else
					std::cout << command[1] << "Terminated succesfully" << "\n";
				delete ppobj;

				continue;
			}
		}
		else
		{
			std::cout << "\n" << "ERROR : Command not found !!!" << "\n";
			continue;
		}
	}

			return 0;

}

