#include "SignatureScanner.h"
#include "stdafx.h"

using namespace std;

SignatureScanner::SignatureScanner()
{
}

SignatureScanner::SignatureScanner(string processName){
	ProcessName = processName;
}

SignatureScanner::~SignatureScanner()
{
}

DWORD SignatureScanner::getPID(){
	return PID;
}

string SignatureScanner::getProcessName(){
	return ProcessName;
}

DWORD SignatureScanner::getSizeofModule(){
	return SizeofModule;
}

DWORD SignatureScanner::getModuleBaseAddress(){
	return ModuleBaseAddress;
}

BOOLEAN SignatureScanner::findModuleInfo(string moduleName) {
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		cout << "CreateToolhelp32Snapshot (of modules)" << endl;
		return false;
	}

	me32.dwSize = sizeof(MODULEENTRY32);

	//  Retrieve information about the first module, 
	//  and exit if unsuccessful 
	if (!Module32First(hModuleSnap, &me32))
	{
		cout << "Module32First" << endl;  // Show cause of failure 
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object! 
		return(FALSE);
	}

	do {
		if (wcscmp(me32.szModule, L"RogueLegacy.exe") == 0) {
			ModuleBaseAddress = (DWORD)me32.modBaseAddr;
			SizeofModule = me32.modBaseSize;
			wcout << "Encontrada la handle del module: " << me32.hModule << endl;
			cout << "Dirección del module: " << ModuleBaseAddress << endl;
			cout << "Tamaño del module: " << SizeofModule << endl;
			return true;
		}
	} while (Module32Next(hModuleSnap, &me32));

	return false;

}

HANDLE SignatureScanner::getProcessHandleAndPID(){
	HANDLE hProcessSnap;
	PROCESSENTRY32 pentry;
	pentry.dwSize = sizeof(PROCESSENTRY32);
	BOOLEAN procesoEncontrado = false;

	wstring processNametemp = wstring(ProcessName.begin(), ProcessName.end());
	LPCWSTR pprocessNametemp = processNametemp.c_str();
	
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("CreateToolhelp32Snapshot (of processes)"));
		return(FALSE);
	}

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pentry))
	{
		_tprintf(TEXT("Process32First")); // show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}
	do {
		//mira si el proceso tiene el nombre que queremos
		//wcout << "[DEBUG] szExeFile=" << pe32.szExeFile << endl;
		if (lstrcmpiW(pentry.szExeFile, pprocessNametemp) == 0) {
			procesoEncontrado = true;
			PID = pentry.th32ProcessID;
			return OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, PID);
			
		}


	} while (!procesoEncontrado && Process32Next(hProcessSnap, &pentry));

	return INVALID_HANDLE_VALUE;

}