#include <winsock2.h>
#include <TlHelp32.h>
#include <Windows.h>
#include <iostream>
#include <string.h>
#include <iomanip>
#include <string> 
#include <memoryapi.h>
#include <Iphlpapi.h>
#include <chrono>
#include <sstream>
#include <time.h>
#include <locale.h>

#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "IPHLPAPI.lib")

#define INFO_BUFFER_SIZE 32767
#define printName std::cout << std::left << std::setw(30) 
#define printData std::cout << std::right << std::setw(40)

void displayDataFromRegistry(const char* label, const char* path, const char* queryPath);
void displayData_TIME_FromRegistry(const char* label, const char* path, const char* queryPath);

#pragma comment(lib, "wbemuuid.lib")

void displayDataFromRegistry(const char* label, const char* path, const char* queryPath) {
	char data[INFO_BUFFER_SIZE];
	memset(data, 0, sizeof(data));
	HKEY hkey;
	DWORD buffer = INFO_BUFFER_SIZE;
	printName << label;
	RegOpenKeyA(HKEY_LOCAL_MACHINE, path, &hkey);
	RegQueryValueExA(hkey, queryPath, NULL, NULL, (LPBYTE)data, &buffer);
	printData << data << std::endl;
	RegCloseKey(hkey);

}


void displayData_TIME_FromRegistry(const char* label, const char* path, const char* queryPath) {
	char data[INFO_BUFFER_SIZE];
	memset(data, 0, sizeof(data));
	HKEY hkey;
	DWORD dwType = REG_DWORD;
	DWORD buffer = INFO_BUFFER_SIZE;
	printName << label;
	RegOpenKeyA(HKEY_LOCAL_MACHINE, path, &hkey);
	RegQueryValueExA(hkey, queryPath, NULL, NULL, (LPBYTE)data, &buffer);
#define len	strlen(data);
	int val[8];
	std::string hexVal;
	std::stringstream ss;

	for (int i = strlen(data) - 1; i >= 0; i--) {
		val[i] = (int)data[i];
		val[i] &= 0xff;

		ss << std::hex << val[i];

	}
	hexVal = ss.str();

	std::stringstream ss2;

	ss2 << std::hex << hexVal;

	long long a = 0;

	ss2 >> a;

	time_t epch = a;

	printData << asctime(gmtime(&epch));

	RegCloseKey(hkey);
}
void systemInfo()
{
	printName << "Host Name: ";
	CHAR host_name[INFO_BUFFER_SIZE];
	memset(host_name, 0, sizeof(host_name));
	DWORD buffer = INFO_BUFFER_SIZE;
	GetComputerNameA(host_name, &buffer);
	printData << host_name << std::endl;

	displayDataFromRegistry("OS Name: ", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");
	displayDataFromRegistry("OS Version: ", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "BuildLab");
	displayDataFromRegistry("OS Manufacturer: ", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\OEM", "Manufacturer");
	displayDataFromRegistry("OS Build Type: ", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentType");

	std::cout << "Registered Organization: " << "\n";

	displayDataFromRegistry("Registered Owner: ", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "RegisteredOwner");
	displayDataFromRegistry("Product ID: ", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	displayData_TIME_FromRegistry("Original Install Date: ", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallDate");

	displayDataFromRegistry("System Manufacturer: ", "HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardManufacturer");
	displayDataFromRegistry("System Model: ", "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName");


	printName << "Processor(s): ";
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	printData << sysinfo.dwNumberOfProcessors << "\n";
	//free(sysinfo);


	displayDataFromRegistry("BIOS Version", "HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVersion");
	displayDataFromRegistry("Windows Directory", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "SystemRoot");
	displayDataFromRegistry("System Director", "SOFTWARE\\Microsoft\\AppV\\Client", "InstallPath");


	//Boot device:
	printName << "Boot Device: ";
	WCHAR  VolumeName[MAX_PATH] = L"";
	//HANDLE FindHandle           = INVALID_HANDLE_VALUE;
	FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));
	std::wcout << std::right << std::setw(35) << VolumeName << std::endl;

	//System Locale
	setlocale(LC_ALL, "");
	printName << "SYstem Locale: ";
	printData << setlocale(LC_ALL, NULL) << std::endl;

	printName << "Input Locale: ";
	printData << setlocale(LC_ALL, NULL) << std::endl;

	//RAM
	MEMORYSTATUSEX memStatus;
	memStatus.dwLength = sizeof(memStatus);
	GlobalMemoryStatusEx(&memStatus);


	printName << "Total Physical Memory: ";
	printData << memStatus.ullTotalPhys << std::endl;

	printName << "Available Physical Memory: ";
	printData << memStatus.ullAvailPhys << std::endl;

	printName << "Virtual Memory: Max Size: ";
	printData << memStatus.ullTotalPageFile << std::endl;

	printName << "Virtual Memory: Available: ";
	printData << memStatus.ullAvailPageFile << std::endl;

	printName << "Virtual Memory: In Use: ";
	printData << memStatus.ullTotalPageFile - memStatus.ullAvailPageFile << std::endl;

	//free(memStatus);

	displayDataFromRegistry("Page File Location(s)", "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management", "PagingFiles");
	displayDataFromRegistry("Logon Server: ", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName");

	//Adapter:
	printName << "Network Card(s): ";

	PIP_ADAPTER_ADDRESSES  pAdapterInfo;
	PIP_ADAPTER_ADDRESSES  pAdapter = NULL;
	DWORD dwRetVal = 0;

	ULONG ulOutBufLen = sizeof(PIP_ADAPTER_ADDRESSES);

	pAdapterInfo = (IP_ADAPTER_ADDRESSES*)malloc(ulOutBufLen);

	dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAdapterInfo, &ulOutBufLen);

	if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_ADDRESSES*)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			std::cout << "Error";
		}
		if (dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
			int count = 0;
			PIP_ADAPTER_ADDRESSES backup = NULL;

			backup = pAdapterInfo;

			while (backup) {
				count += 1;
				backup = backup->Next;
			}

			pAdapter = pAdapterInfo;
			std::cout << std::right << std::setw(30 - 8) << count;
			std::cout << " NIC(s) Installed." << std::endl;

			while (pAdapter) {
				std::wcout << std::right << std::setw(70) << pAdapter->FriendlyName << std::endl;
				std::wcout << std::right << std::setw(70) << pAdapter->Description << std::endl;
				std::cout << std::right << std::setw(70) << pAdapter->AdapterName << std::endl;
				//std::cout << std::right << std::setw(70) << pAdapter->Dhcpv4Server  << std::endl;

				std::cout << "\n";

				pAdapter = pAdapter->Next;

			}
		}
	}
}



int main() {
	systemInfo();
	std::cout << "\n Task2: Print all ERW region of process:\n";
	MEMORY_BASIC_INFORMATION mbi = {};
	LPVOID offset = 0;
	HANDLE process = NULL;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	DWORD bytesWritten = 0;

	Process32First(snapshot, &processEntry);
	while (Process32Next(snapshot, &processEntry))
	{
		process = OpenProcess(MAXIMUM_ALLOWED, false, processEntry.th32ProcessID);
		if (process)
		{
			
			while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi)))
			{
				offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
				if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
				{
					std::wcout << processEntry.szExeFile << "\n";
					std::cout << "\tRWX: 0x" << std::hex << mbi.BaseAddress << "\n";
				}
			}
			offset = 0;
		}
		CloseHandle(process);
	}

	return 0;
}