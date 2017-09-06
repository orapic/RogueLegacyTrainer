// TestInyection.cpp: define el punto de entrada de la aplicación de consola.

#include "stdafx.h"


using namespace std;


// Detectar si un programa está en ejecucion
DWORD getProcessEntry(string processName, PROCESSENTRY32& pentry);
//Conseguir direccion base de un modulo
DWORD_PTR dwGetModuleBaseAddress(DWORD dwProcID, TCHAR *szModuleName);
// TODO? Conseguir direccion de stack del thread0
HANDLE getThread0Handle(DWORD processID);
// Conseguir direccion de una cadena de punteros
DWORD findAddressWithPointers(HANDLE hProc, int PointerLevel, DWORD BaseAddress, DWORD Pointers[]);
// Funcion para leer memoria
template<typename T>
T readMemory(HANDLE proc, LPVOID adr) {
	T val;
	ReadProcessMemory(proc, adr, &val, sizeof(T), NULL);
	return val;
}
// Funcion para escribir la memoria
template<typename T>
void writeMemory(HANDLE proc, LPVOID adr, T val) {
	WriteProcessMemory(proc, adr, &val, sizeof(T), NULL);
}

template<typename T>
DWORD protectMemory(HANDLE proc, LPVOID adr, DWORD prot) {
	DWORD oldProt;
	VirtualProtectEx(proc, adr, sizeof(T), prot, &oldProt);
	return oldProt;
}


string processName;
PROCESSENTRY32 pe32;
DWORD PID;
HANDLE gameProcesshdl;

// OFFSETS HP 
DWORD offsetsHP[] = { 0x658, 0x1fc,  0x118};

int _tmain(int argc, _TCHAR* argv[])
{
	processName = "RogueLegacy.exe";

	SignatureScanner sigscan = SignatureScanner(processName);

	wcout << "--------ROGUE LEGACY TRAINER PLEB VERSION--------" << endl;

	cout << "Comprobando si esta "<< processName << " entre los procesos"<< endl;

	gameProcesshdl = sigscan.getProcessHandleAndPID();

	if (gameProcesshdl != INVALID_HANDLE_VALUE || gameProcesshdl == NULL) {

		PID = sigscan.getPID();

		cout << "se ha econtrado " << processName << ", con PID : " << PID << endl;
		
		sigscan.findModuleInfo("RogueLegacy");

		DWORD moduleBaseAddress = sigscan.getModuleBaseAddress();
		DWORD moduleSize = sigscan.getSizeofModule();

		
		//gameBaseAddress = LPVOID(dwGetModuleBaseAddress(PID, _T("RogueLegacy.exe")));

		//wcout << "El proceso se ha cargado en la direccion : " << gameBaseAddress << endl;
		wcout << "Freezing HP to 999" << endl;
		cout << sizeof(DWORD) << endl;

		// Calculando la direccion de la HP
		
		if (moduleBaseAddress != 0) {
			
			//Prueba NOPear la función que actualiza la vida 
			BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
			//0F5D6327 --- \x8B\xF1\x89\x96\x18\x01
			BYTE originalbytes[] = { 0x8B, 0xF1, 0x89, 0x96, 0x18, 0x01};
			BYTE tempbytes[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
			//Direccion destino a sobreescribir
			DWORD addressfunctionHPRefresh = moduleBaseAddress;
			BOOL bytesFound = FALSE;
			DWORD addressfunction = 0x0F5D6327;

			while (!bytesFound) {
				cout << "\r Analizando la direccion: " << addressfunctionHPRefresh;
				int n;
				DWORD oldProt;
				oldProt = protectMemory<DWORD>(gameProcesshdl, LPVOID(addressfunctionHPRefresh), PAGE_READWRITE); 
				ReadProcessMemory(gameProcesshdl, LPVOID(addressfunctionHPRefresh), tempbytes, sizeof(tempbytes),NULL);
				n = memcmp(tempbytes, originalbytes, sizeof(originalbytes));
				protectMemory<DWORD>(gameProcesshdl, LPVOID(addressfunctionHPRefresh), oldProt);
				if (n == 0){
					bytesFound = TRUE;
					cout << "Hemos llegado a la  direccion" << endl;
					break;
				}
				addressfunctionHPRefresh++;
				
				if (addressfunctionHPRefresh - moduleBaseAddress > moduleSize) {
					break;
				}
			}
			if (bytesFound){
				addressfunctionHPRefresh = addressfunctionHPRefresh + 2;
				DWORD oldProt;
				oldProt = protectMemory<DWORD>(gameProcesshdl, LPVOID(addressfunctionHPRefresh), PAGE_READWRITE);
				WriteProcessMemory(gameProcesshdl, LPVOID(addressfunctionHPRefresh), nops, sizeof(nops), NULL);
				protectMemory<DWORD>(gameProcesshdl, LPVOID(addressfunctionHPRefresh), oldProt);

			}


			system("pause");
			CloseHandle(gameProcesshdl);
			return 0;


		}
		

	} else{
		cout << "No se ha encontrado" << endl;
	}
	
	
	CloseHandle(gameProcesshdl);
	system("pause");
	return 0;
}


/* // Funcion original
DWORD getProcessEntry(string processName, PROCESSENTRY32& pentry) {
	HANDLE hProcessSnap;
	
	
	BOOLEAN procesoEncontrado = false;

	wstring processNametemp = wstring(processName.begin(), processName.end());
	LPCWSTR pporcessNametemp = processNametemp.c_str();
	printf("Hola estoy dentro getProcessID \n");
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
		if (lstrcmpiW(pe32.szExeFile, pporcessNametemp) == 0) {
			procesoEncontrado = true;
			PID = pentry.th32ProcessID;
			break;
		}
		

	} while (!procesoEncontrado && Process32Next(hProcessSnap, &pe32));
		
	return procesoEncontrado;
}
*/

//Get the base address of the loaded module
DWORD_PTR dwGetModuleBaseAddress(DWORD dwProcID, TCHAR *szModuleName)
{
	DWORD_PTR dwModuleBaseAddress = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcID);
	wcout << "GetLastError()=" << GetLastError() << endl;
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 ModuleEntry32;
		ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &ModuleEntry32))
		{
			do
			{
				
				if (_tcsicmp(ModuleEntry32.szModule, szModuleName) == 0)
				{	
					
					dwModuleBaseAddress = (DWORD_PTR)ModuleEntry32.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnapshot, &ModuleEntry32));
		}
		CloseHandle(hSnapshot);
	}
	return dwModuleBaseAddress;
}



HANDLE getThread0Handle(DWORD processID){
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	HANDLE hThread=INVALID_HANDLE_VALUE;
	BOOL threadFound = false;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}

	do
	{
		if (te32.th32OwnerProcessID == processID)
		{
			_tprintf(TEXT("\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
			_tprintf(TEXT("\n     base priority  = %d"), te32.tpBasePri);
			_tprintf(TEXT("\n     delta priority = %d"), te32.tpDeltaPri);
			threadFound = true;
			break;
		}
	} while (Thread32Next(hThreadSnap, &te32));

	_tprintf(TEXT("\n"));

	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);

	if (threadFound) {
		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
	}

	return hThread;

}

DWORD findAddressWithPointers(HANDLE hProc, int PointerLevel, DWORD BaseAddress, DWORD offsets[]){
	DWORD baseAddress = BaseAddress;
	DWORD tempPointer;

	for (int c = 0; c < PointerLevel; c++) {
		if (c == 0){
			tempPointer = readMemory<DWORD>(hProc, LPVOID(baseAddress));
		}
		tempPointer = tempPointer + offsets[c];
		tempPointer = readMemory<DWORD>(hProc, LPVOID(tempPointer));
	}
	return readMemory<DWORD>(hProc, LPVOID(tempPointer));
}


/* //Prueba para leer punteros
DWORD HPAddress = 0;
HPAddress = findAddressWithPointers(gameProcesshdl, 3, DWORD(gameBaseAddress) + 0xF0E30, offsetsHP);
DWORD HPValue = readMemory<DWORD>(gameProcesshdl, LPVOID(HPAddress));
printf("Direccion de HP : 0x%8x", DWORD(HPAddress));
//*/

//wcout << "La direccion de la HP es: " << HPAddress << ", y su valor es: " << HPValue << endl;


/*
printf("HEX : 0x%8x", DWORD(HPAddress));
printf("/n");
//wcout << "Valor de la direccion de HP:" << DWORD(HPAddress) << endl;
while (1) {
DWORD oldProt;
oldProt = protectMemory<DWORD>(gameProcesshdl, gameBaseAddress, PAGE_READWRITE);
writeMemory<DWORD>(gameProcesshdl, gameBaseAddress, 999);
protectMemory<DWORD>(gameProcesshdl, gameBaseAddress, oldProt);
}
*/