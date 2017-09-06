#pragma once
#include "stdafx.h"

using namespace std;

class SignatureScanner
{
public:
	//Default Constructor
	SignatureScanner();
	//Overload 
	SignatureScanner(string processName);
	~SignatureScanner();
	
	// Consigue un Handle del proceso y su PID
	HANDLE getProcessHandleAndPID();

	//Getter del PID
	DWORD getPID();

	//Getter del Nombre del proceso
	string getProcessName();

	//Getter del Tamaño del Module
	DWORD getSizeofModule();

	//Getter del Base Address del Module
	DWORD getModuleBaseAddress();

	// Conseguir el tamaño y handle para el modulo
	BOOLEAN findModuleInfo(string moduleName);
private: 
	//Name of the process
	string ProcessName;
	// Handle of the process
	HANDLE ProcessHandle;
	// PID 
	DWORD PID;
	// Base address of Module
	DWORD ModuleBaseAddress;
	// Size of Module
	DWORD SizeofModule;

};

