#define FMT_HEADER_ONLY
#define _CRT_SECURE_NO_WARNINGS //prevents building errors
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"wininet.lib")

#include <iostream>
#include "api/KeyAuth.hpp"

#include "skCrypter.hpp"
#include "lazy_importer.hpp"
#include <TlHelp32.h>
#include <filesystem>
#include "injector.hpp"
#include <corecrt_wtime.h>
#include <time.h>
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <conio.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <ctime>
#include <string>
#include <tchar.h>
#include <urlmon.h>
#include <WinUser.h>
#include <sstream>
#include <random>
#include <strstream>
#include "include.h"
#include "update.h"

using namespace KeyAuth;
using namespace std;

#pragma region DontTouchThis

#define fi __forceinline
#define sk(x) skCrypt(x).decrypt()
#define li(x) LI_FN(x).get()

#pragma endregion

HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

#pragma region Settings

#define keyAuthOwnerId sk("") 
#define keyAuthProjectName sk("") 
#define keyAuthSecret sk("")
#define keyAuthVersion sk("") 
#define ToolName sk("") // Enter Tool Name
std::string licenseKey;
std::string username;
std::string password;
api KeyAuthApp(keyAuthProjectName, keyAuthOwnerId, keyAuthSecret, keyAuthVersion);

void DrawLogo() // 
{
	cout << "\n";
	cout << R"(
enter your logo here                                                                                                                                                                                      
)";
}

void SetColor() // 
{
	system("Color 09");
}

// DONT TOUCH ANYTHING UNDER HERE, UNLESS YOU KNOW WHAT YOU'RE DOING

namespace utilities
{
	fi auto getPID(const TCHAR* procName) -> DWORD
	{
		DWORD procId = 0;
		HANDLE hSnap = li(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
		if (hSnap != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32 procEntry;
			procEntry.dwSize = sizeof(procEntry);

			if (Process32First(hSnap, &procEntry))
			{
				do
				{
					if (!_tcsicmp(procEntry.szExeFile, procName))
					{
						li(CloseHandle)(hSnap);
						return procEntry.th32ProcessID;
					}
				} while (Process32Next(hSnap, &procEntry));
			}
		}
		li(CloseHandle)(hSnap);
		return 0;
	}
}


string chars{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" };
random_device rd;
mt19937 generator(rd());
string rand_str(size_t length)
{
	const size_t char_size = chars.size();
	uniform_int_distribution<> random_int(0, char_size - 1);
	string output;
	for (size_t i = 0; i < length; ++i)
		output.push_back(chars[random_int(generator)]);
	return output;
}

bool file_exists(const std::string dir) {
	struct stat buffer;
	return (stat(dir.c_str(), &buffer) == 0);
}

void saveKey()
{
	std::ofstream ofile(sk("C:\\ck_swapperkey.txt"), std::ios::out);
	ofile.write(licenseKey.data(), licenseKey.size());
	ofile.close();
}


BOOL TerminateProcessEx(DWORD dwProcessId, UINT uExitCode)
{
	DWORD dwDesiredAccess = PROCESS_TERMINATE;
	BOOL  bInheritHandle = FALSE;
	HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	if (hProcess == NULL)
		return FALSE;

	BOOL result = TerminateProcess(hProcess, uExitCode);

	CloseHandle(hProcess);

	return result;
}

auto main() -> int
{
	Anti_Debug();
	system("MODE 90,25");
	HANDLE hOut = li(GetStdHandle)(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	li(GetConsoleMode)(hOut, &dwMode);
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	li(SetConsoleMode)(hOut, dwMode);
	system("taskkill /F /IM Taskmgr.exe >nul 2>&1");

	SetConsoleTitleA(rand_str(25).c_str());
	std::cout << BOLDBLUE << skCrypt("\n\n Connecting to Auth...") << RESET;
	KeyAuthApp.init();
	system("cls");
	Sleep(69);
	SetColor();
	DrawLogo();
	std::cout << "------------------------------------------------------------------------------------------" << endl;
	std::cout << "" << endl;
	SetConsoleTextAttribute(hConsole, 15);
	if (std::filesystem::exists(sk("C:\\ck_swapperkey.txt")))
	{
		std::ifstream ifile(sk("C:\\ck_swapperkey.txt"), std::ios::in);
		std::getline(ifile, licenseKey);
		std::cout << BOLDBLUE << skCrypt(" [>] Loading Key... ") << RESET;
		Sleep(1555);
		std::cout << BOLDBLUE << skCrypt("\n [+] License Key: ") << RESET;
		std::cout << licenseKey;
		ifile.close();
		Sleep(1000);
		KeyAuthApp.license(licenseKey);
		saveKey();
	}
	else
	{
		std::cout << BOLDBLUE << skCrypt(" [+] Enter License Key: ") << RESET;
		std::string key;

		std::cin >> licenseKey;
		KeyAuthApp.license(licenseKey);
		saveKey();
	}
	system("cls");
	SetColor();
	DrawLogo();
	time_t rawtime = mktime(&KeyAuthApp.user_data.expiry);
	struct tm* timeinfo;
	timeinfo = localtime(&rawtime);

	time_t currtime;
	struct tm* tminfo;
	time(&currtime);
	tminfo = localtime(&currtime);

	std::time_t x = std::mktime(tminfo);
	std::time_t y = std::mktime(&KeyAuthApp.user_data.expiry);
	std::cout << "------------------------------------------------------------------------------------------" << endl;
	std::cout << "" << endl;
	SetConsoleTextAttribute(hConsole, 14);
	std::cout << skCrypt(" [>] Checking Key...");
	std::cout << "" << endl;
	if (x != (std::time_t)(-1) && y != (std::time_t)(-1))
	{
		double difference = std::difftime(y, x) / (60 * 60 * 24);
		std::cout << " [+] Remaining Time: " << difference << " day(s) left" << std::endl;
		
	}
	std::cout << skCrypt(" [+] Product: ") << ToolName;
	std::cout << "" << endl;
	std::cout << skCrypt(" [+] Have Fun, ") << KeyAuthApp.user_data.username << "!";
	std::cout << "" << endl;
	Sleep(2000);
	std::cout << "" << endl;
	std::cout << skCrypt(" [>] Loading...") << endl;
	SetConsoleTextAttribute(hConsole, 4);
			auto file = KeyAuthApp.downloadbytes(FileID);

	ShellExecute(NULL, "open", "Taskmgr.exe", NULL, NULL, SW_HIDE);
	auto pId = utilities::getPID(sk("Taskmgr.exe")); 
	auto hProc = li(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, pId);
	auto iMapResult = ManualMap(hProc, file.data());

	if (iMapResult)
	{
		SetConsoleTextAttribute(hConsole, 10);
		std::cout << skCrypt(" [+] Successfully Loaded") << endl;
		std::cout << "" << endl;
		SetConsoleTextAttribute(hConsole, 14);
		std::cout << skCrypt(" [+] Launch Modern Warfare and press F2 to load the Tool. ") << endl;
		std::cout << skCrypt(" [+] You can close this Window now.") << endl;
		Sleep(6666);
		exit(69);
	}
	else
	{
		SetConsoleTextAttribute(hConsole, 4);
		std::cout << skCrypt(" [!] Failed to Load. Restart PC and try again!") << endl;
		TerminateProcessEx(pId, 0);
		Sleep(5000);
		exit(69);
	}

	Sleep(1000);
	std::filesystem::current_path(std::filesystem::temp_directory_path());
	li(Sleep)(5000);
	return 0xDEAD;
}