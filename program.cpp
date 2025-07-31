#include <Windows.h>
#include <iostream>

static FARPROC GetFunctionAddress(LPCSTR functionName, LPCWSTR libraryName) {
	HMODULE library = GetModuleHandle(libraryName);
	if (library == NULL) {
		library = LoadLibrary(libraryName);
	}
	return GetProcAddress(library, functionName);
}
// NOTE RtlSetProcessIsCritical requires the SE_DEBUG_NAME privilege to be enabled for the caller process token.
namespace {
	typedef NTSTATUS(WINAPI* PRtlSetProcessIsCritical) (
		IN  BOOLEAN  bNew,      // new setting for process
		OUT BOOLEAN* pbOld,     // pointer which receives old setting (can be null)
		IN  BOOLEAN  bNeedScb); // need system critical breaks
}
static void SetSystemCritical(BOOLEAN critical)
{
	PRtlSetProcessIsCritical RtlSetCriticalProcess = reinterpret_cast<PRtlSetProcessIsCritical>(GetFunctionAddress("RtlSetProcessIsCritical", L"ntdll.dll"));
	RtlSetCriticalProcess(critical, NULL, FALSE);
}

LUID EzLookupPrivilege(LPCWSTR privilege) {
	LUID output = { };
	LookupPrivilegeValue(NULL, privilege, &output);
	return output;
}
void EzEnablePrivilege(HANDLE token, LUID privilege) {
	TOKEN_PRIVILEGES tp = { };
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = privilege;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
}
HANDLE EzOpenCurrentToken() {
	HANDLE output = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &output);
	return output;
}

void main() {
	HANDLE currentToken = EzOpenCurrentToken();
	LUID debugPrivilege = EzLookupPrivilege(SE_DEBUG_NAME);
	EzEnablePrivilege(currentToken, debugPrivilege);
	SetSystemCritical(TRUE);
	ExitProcess(0);
}