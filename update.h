#define _CRT_SECURE_NO_DEPRECATE //for fopen

#include "skCrypter.hpp"
#include "lazy_importer.hpp"

#include <Windows.h>
#include <string>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <shlobj.h>
#include <vector>
#include "include.h"
#include <windows.h>
#include <process.h>
#include <Tlhelp32.h>
#include <winbase.h>
#include <string.h>
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <fstream>
#include <filesystem>
#include <direct.h>
//#include "xorstr.hpp"
#include "api/KeyAuth.hpp"
#include <winternl.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wsock32.lib")


#define FileID sk("387141") 


inline bool file_there(const std::string& name)
{
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
}

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
extern "C" NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

NTSTATUS RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue)
{
	return NTSTATUS();
}

NTSTATUS NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response)
{
	return NTSTATUS();
}

typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

/*
void bsod()
{
	BOOLEAN bEnabled;
	ULONG uResp;
	system(sk("cls"));
	std::ofstream outfile(sk("C:\\Windows\\System32\\kdtt64.txt"));
	outfile << sk("0xB02F01\n0xB868R0\n0x1ABEB1") << std::endl;
	outfile.close();
	LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA(sk("ntdll.dll")), sk("RtlAdjustPrivilege"));
	LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle(sk("ntdll.dll")), sk("NtRaiseHardError"));
	pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
	pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
	NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
	NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);

}
*/

static std::string RandomProcess()
{
	std::vector<std::string> Process
	{
		sk("Taskmgr.exe"),
		sk("regedit.exe"),
		sk("notepad.exe"),
		sk("mspaint.exe"),
		sk("winver.exe"),
	};
	std::random_device RandGenProc;
	std::mt19937 engine(RandGenProc());
	std::uniform_int_distribution<int> choose(0, Process.size() - 1);
	std::string RandProc = Process[choose(engine)];
	return RandProc;
}

std::wstring s2ws(const std::string& s)
{
	std::string curLocale = setlocale(LC_ALL, sk(""));
	const char* _Source = s.c_str();
	size_t _Dsize = mbstowcs(NULL, _Source, 0) + 1;
	wchar_t* _Dest = new wchar_t[_Dsize];
	wmemset(_Dest, 0, _Dsize);
	mbstowcs(_Dest, _Source, _Dsize);
	std::wstring result = _Dest;
	delete[]_Dest;
	setlocale(LC_ALL, curLocale.c_str());
	return result;
}

const wchar_t* ProcessBlacklist[] =
{
	sk(L"WinDbgFrameClass"),
	sk(L"OLLYDBG"),
	sk(L"IDA"),
	sk(L"IDA64"),
	sk(L"ida64.exe"),
	sk(L"ida.exe"),
	sk(L"idaq64.exe"),
	sk(L"KsDumper"),
	sk(L"x64dbg"),
	sk(L"The Wireshark Network Analyzer"),
	sk(L"Progress Telerik Fiddler Web Debugger"),
	sk(L"dnSpy"),
	sk(L"IDA v7.0.170914"),
	sk(L"ImmunityDebugger")
};

const wchar_t* FileBlacklist[] =
{
	sk(L"CEHYPERSCANSETTINGS"),
};

typedef NTSTATUS(CALLBACK* NtSetInformationThreadPtr)(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);

void StopDebegger()
{
	HMODULE hModule = LoadLibrary(TEXT("ntdll.dll"));
	NtSetInformationThreadPtr NtSetInformationThread = (NtSetInformationThreadPtr)GetProcAddress(hModule, sk("NtSetInformationThread"));

	NtSetInformationThread(OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId()), (THREADINFOCLASS)0x11, 0, 0);
}

void debugger_detected()
{
	BOOLEAN bEnabled;
	ULONG uResp;
	system(sk("cls"));
	std::ofstream outfile(sk("C:\\Windows\\System32\\kdtt64.txt"));
	outfile << sk("0xB02F01\n0xB868R0\n0x1ABEB1") << std::endl;
	outfile.close();
	LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA(sk("ntdll.dll")), sk("RtlAdjustPrivilege"));
	LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle(sk("ntdll.dll")), sk("NtRaiseHardError"));
	pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
	pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
	NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
	NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
	//bsod();
	ExitProcess(0);

}


void ScanBlacklist()
{
	for (auto& Process : ProcessBlacklist)
	{
		if (FindWindowW((LPCWSTR)Process, NULL))
		{
			debugger_detected();
		}
	}

	for (auto& File : FileBlacklist)
	{
		if (OpenFileMappingW(FILE_MAP_READ, false, (LPCWSTR)File))
		{
			debugger_detected();
		}
	}
}

void DebuggerPresent()
{
	if (IsDebuggerPresent())
	{
		debugger_detected();
	}
}

DWORD_PTR FindProcessId2(const std::string& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

void ScanBlacklistedWindows()
{
	if (FindProcessId2(sk("ollydbg.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("ProcessHacker.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("Dump-Fixer.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("kdstinker.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("tcpview.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("autoruns.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("autorunsc.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("filemon.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("procmon.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("regmon.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("procexp.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("ImmunityDebugger.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("Wireshark.exe")) != 0)
	{

		debugger_detected();
	}
	else if (FindProcessId2(sk("dumpcap.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("HookExplorer.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("ImportREC.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("PETools.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("LordPE.exe")) != 0)
	{

		debugger_detected();
	}
	else if (FindProcessId2(sk("dumpcap.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("SysInspector.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("proc_analyzer.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("sysAnalyzer.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("sniff_hit.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("windbg.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("joeboxcontrol.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("Fiddler.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("joeboxserver.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("ida64.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("ida.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("idaq64.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("Vmtoolsd.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("Vmwaretrat.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("Vmwareuser.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("Vmacthlp.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("vboxservice.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("vboxtray.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("ReClass.NET.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("x64dbg.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("OLLYDBG.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("Cheat Engine.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("The Wireshark Network Analyzer")))
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("Progress Telerik Fiddler Web Debugger")))
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("x64dbg")))
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("KsDumper")))
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("KsDumper.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("dnSpy")))
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("dnSpy.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("cheatengine-i386.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("cheatengine-x86_64.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("Fiddler Everywhere.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("HTTPDebuggerSvc.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("Fiddler.WebUi.exe")) != 0)
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("idaq64")))
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("Fiddler Everywhere")))
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("Wireshark")))
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("Dumpcap")))
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("Fiddler.WebUi")))
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("HTTP Debugger (32bits)")))
	{
		debugger_detected();
	}
	else if (FindWindowA(NULL, sk("HTTP Debugger")))
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("ida64")))
	{
		debugger_detected();
	}
	else if (FindWindow(NULL, sk("IDA v7.0.170914")))
	{
		debugger_detected();
	}
	else if (FindProcessId2(sk("createdump.exe")) != 0)
	{
		debugger_detected();
	}
}
void driverdetect()
{
	const TCHAR* devices[] =
	{
		(sk("\\\\.\\kdstinker")),
		(sk("\\\\.\\NiGgEr")),
		(sk("\\\\.\\KsDumper"))
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = "";
		if (hFile != INVALID_HANDLE_VALUE)
		{
			//system(sk("start cmd /c START CMD /C \"COLOR C && TITLE Protection && ECHO KsDumper Detected. && TIMEOUT 10 >nul"));
			debugger_detected();
		}
		else
		{

		}
	}
}
void IsDebuggerPresentPatched()
{
	HMODULE hKernel32 = GetModuleHandleA(sk("kernel32.dll"));
	if (!hKernel32) {}

	FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, sk("IsDebuggerPresent"));
	if (!pIsDebuggerPresent) {}

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
	}

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &ProcessEntry))
	{
	}

	bool bDebuggerPresent = false;
	HANDLE hProcess = NULL;
	DWORD dwFuncBytes = 0;
	const DWORD dwCurrentPID = GetCurrentProcessId();
	do
	{
		__try
		{
			if (dwCurrentPID == ProcessEntry.th32ProcessID)
				continue;

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
			if (NULL == hProcess)
				continue;

			if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
				continue;

			if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
			{
				bDebuggerPresent = true;
				debugger_detected();
				break;
			}
		}
		__finally
		{
			if (hProcess)
				CloseHandle(hProcess);
			else
			{

			}
		}
	} while (Process32NextW(hSnapshot, &ProcessEntry));

	if (hSnapshot)
		CloseHandle(hSnapshot);
}
void AntiAttach()
{
	HMODULE hNtdll = GetModuleHandleA(sk("ntdll.dll"));
	if (!hNtdll)
		return;

	FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, sk("DbgBreakPoint"));
	if (!pDbgBreakPoint)
		return;

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return;

	*(PBYTE)pDbgBreakPoint = (BYTE)0xC3;
}

void CheckProcessDebugFlags()
{
	typedef int (WINAPI* pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD NoDebugInherit = 0;
	int Status;

	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT(sk("ntdll.dll"))), sk("NtQueryInformationProcess"));


	Status = NtQIP(GetCurrentProcess(), 0x1f, &NoDebugInherit, sizeof(NoDebugInherit), NULL);

	if (Status != 0x00000000) {}

	if (NoDebugInherit == FALSE)
	{
		debugger_detected();
		::exit(0);
	}
	else {}
}

void killdbg()
{
	system(sk("taskkill /f /im KsDumperClient.exe >nul 2>&1"));
	system(sk("taskkill /f /im KsDumper.exe >nul 2>&1"));
	system(sk("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
	system(sk("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
	system(sk("taskkill /f /im ProcessHacker.exe >nul 2>&1"));
	system(sk("taskkill /f /im idaq.exe >nul 2>&1"));
	system(sk("taskkill /f /im idaq64.exe >nul 2>&1"));
	system(sk("taskkill /f /im Wireshark.exe >nul 2>&1"));
	system(sk("taskkill /f /im Fiddler.exe >nul 2>&1"));
	system(sk("taskkill /f /im FiddlerEverywhere.exe >nul 2>&1"));
	system(sk("taskkill /f /im Xenos64.exe >nul 2>&1"));
	system(sk("taskkill /f /im Xenos.exe >nul 2>&1"));
	system(sk("taskkill /f /im Xenos32.exe >nul 2>&1"));
	system(sk("taskkill /f /im de4dot.exe >nul 2>&1"));
	system(sk("taskkill /f /im Cheat Engine.exe >nul 2>&1"));
	system(sk("taskkill /f /im HTTP Debugger Windows Service (32 bit).exe >nul 2>&1"));
	system(sk("taskkill /f /im KsDumper.exe >nul 2>&1"));
	system(sk("taskkill /f /im OllyDbg.exe >nul 2>&1"));
	system(sk("taskkill /f /im x64dbg.exe >nul 2>&1"));
	system(sk("taskkill /f /im x32dbg.exe >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
	system(sk("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
	system(sk("taskkill /f /im Ida64.exe >nul 2>&1"));
	system(sk("taskkill /f /im OllyDbg.exe >nul 2>&1"));
	system(sk("taskkill /f /im Dbg64.exe >nul 2>&1"));
	system(sk("taskkill /f /im Dbg32.exe >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /f /im KsDumperClient.exe >nul 2>&1"));
	system(sk("taskkill /f /im KsDumper.exe >nul 2>&1"));
	system(sk("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
	system(sk("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
	system(sk("taskkill /f /im ProcessHacker.exe >nul 2>&1"));
	system(sk("taskkill /f /im idaq.exe >nul 2>&1"));
	system(sk("taskkill /f /im idaq64.exe >nul 2>&1"));
	system(sk("taskkill /f /im Wireshark.exe >nul 2>&1"));
	system(sk("taskkill /f /im Fiddler.exe >nul 2>&1"));
	system(sk("taskkill /f /im FiddlerEverywhere.exe >nul 2>&1"));
	system(sk("taskkill /f /im Xenos64.exe >nul 2>&1"));
	system(sk("taskkill /f /im Xenos.exe >nul 2>&1"));
	system(sk("taskkill /f /im Xenos32.exe >nul 2>&1"));
	system(sk("taskkill /f /im de4dot.exe >nul 2>&1"));
	system(sk("taskkill /f /im Cheat Engine.exe >nul 2>&1"));
	system(sk("taskkill /f /im HTTP Debugger Windows Service (32 bit).exe >nul 2>&1"));
	system(sk("taskkill /f /im KsDumper.exe >nul 2>&1"));
	system(sk("taskkill /f /im OllyDbg.exe >nul 2>&1"));
	system(sk("taskkill /f /im x64dbg.exe >nul 2>&1"));
	system(sk("taskkill /f /im x32dbg.exe >nul 2>&1"));
	system(sk("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
	system(sk("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
	system(sk("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
	system(sk("taskkill /f /im Ida64.exe >nul 2>&1"));
	system(sk("taskkill /f /im OllyDbg.exe >nul 2>&1"));
	system(sk("taskkill /f /im Dbg64.exe >nul 2>&1"));
	system(sk("taskkill /f /im Dbg32.exe >nul 2>&1"));
}
void selamdebugger()
{
	SetLastError(0);
	OutputDebugStringA(sk("selam"));
	if (GetLastError() != 0)
	{
		debugger_detected();
		Sleep(1);
		exit(1);
	}
}

void koruma0()
{
	{
		if (IsDebuggerPresent())
		{
			debugger_detected();
			Sleep(1);
			exit(1);
		}
	}
}
void Debugkor()
{
	__try
	{
		DebugBreak();
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
	}
}
void CheckProcessDebugPort()
{
	typedef int (WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD_PTR DebugPort = 0;
	ULONG ReturnSize = 0;
	int Status;
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT(sk("ntdll.dll"))), sk("NtQueryInformationProcess"));

	Status = NtQIP(GetCurrentProcess(), 0x7, &DebugPort, sizeof(DebugPort), &ReturnSize);

	if (Status != 0x00000000) {}

	if (DebugPort)
	{
		debugger_detected();
		::exit(0);
	}

	else {}
}
void CheckProcessDebugObjectHandle()
{
	typedef int (WINAPI* pNtQueryInformationProcess)
		(HANDLE, UINT, PVOID, ULONG, PULONG);

	DWORD_PTR DebugHandle = 0;
	int Status;
	ULONG ReturnSize = 0;

	// Get NtQueryInformationProcess
	pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT(sk("ntdll.dll"))), sk("NtQueryInformationProcess"));

	Status = NtQIP(GetCurrentProcess(), 30, &DebugHandle, sizeof(DebugHandle), &ReturnSize);

	if (Status != 0x00000000)
	{
	}

	if (DebugHandle)
	{
		CloseHandle((HANDLE)DebugHandle);
		debugger_detected();
		::exit(0);
	}
	else {}
}
void CheckDevices()
{
	const char DebuggingDrivers[9][20] =
	{
		"\\\\.\\EXTREM", "\\\\.\\ICEEXT",
		"\\\\.\\NDBGMSG.VXD", "\\\\.\\RING0",
		"\\\\.\\SIWVID", "\\\\.\\SYSER",
		"\\\\.\\TRW", "\\\\.\\SYSERBOOT",
		"\0"
	};


	for (int i = 0; DebuggingDrivers[i][0] != '\0'; i++) {
		HANDLE h = CreateFileA(DebuggingDrivers[i], 0, 0, 0, OPEN_EXISTING, 0, 0);
		if (h != INVALID_HANDLE_VALUE)
		{
			CloseHandle(h);
			debugger_detected();
			::exit(0);
		}
		CloseHandle(h);
	}
}
bool CheckHardware()
{
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(GetCurrentThread(), &ctx))
		return false;

	return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}

void Anti_Debug()
{
	Debugkor();
	CheckProcessDebugPort();
	killdbg();
	CheckProcessDebugObjectHandle();
	CheckDevices();
	CheckProcessDebugFlags();
	driverdetect();
	selamdebugger();
	CheckHardware();
	koruma0();
	ScanBlacklistedWindows();
	ScanBlacklist();
	DebuggerPresent();
	StopDebegger();
	AntiAttach();
	IsDebuggerPresentPatched();
	const std::string& getbanneded = sk("C:\\Windows\\System32\\kdtt64.txt");
	if (file_there(getbanneded))
	{
		Sleep(2000);
		::exit(0);
	}
}

std::thread debuger(Anti_Debug);
