#define WINVER 0x0601
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <tlhelp32.h>

typedef LONG NTSTATUS;

typedef enum _PROCESSINFOCLASS
{
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef NTSTATUS (WINAPI *PFN_NtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

#define BUF_SIZE 2048
#define MAX_PID_COUNT 256

static DWORD pidList[MAX_PID_COUNT];
static int pidCount = 0;

static BOOL AddPid(DWORD pid)
{
    if (pidCount >= MAX_PID_COUNT)
        return FALSE;

    for (int i = 0; i < pidCount; i++)
    {
        if (pidList[i] == pid)
            return FALSE;
    }
    pidList[pidCount++] = pid;
    return TRUE;
}

static void CollectChildren(DWORD parentPid)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnap, &pe))
    {
        CloseHandle(hSnap);
        return;
    }

    do
    {
        if (pe.th32ParentProcessID == parentPid)
        {
            if (AddPid(pe.th32ProcessID))
            {
                CollectChildren(pe.th32ProcessID);
            }
        }
    } while (Process32NextW(hSnap, &pe));

    CloseHandle(hSnap);
}

static DWORD FindRootPid(const wchar_t *exeName)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnap, &pe))
    {
        CloseHandle(hSnap);
        return 0;
    }

    do
    {
        if (_wcsicmp(pe.szExeFile, exeName) == 0)
        {
            CloseHandle(hSnap);
            return pe.th32ProcessID;
        }
    } while (Process32NextW(hSnap, &pe));

    CloseHandle(hSnap);
    return 0;
}

static BOOL EnableDebugPrivilege(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken))
    {
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return (err == ERROR_SUCCESS);
}

static BOOL ClearBreakFlag(DWORD pid, PFN_NtSetInformationProcess pNtFunc)
{
    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (hProc == NULL)
        return FALSE;

    ULONG val = 0;
    NTSTATUS status = pNtFunc(hProc, ProcessBreakOnTermination, &val, sizeof(ULONG));
    CloseHandle(hProc);

    return status >= 0;
}

static BOOL TerminateTarget(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc == NULL)
        return FALSE;

    BOOL ok = TerminateProcess(hProc, 0);
    CloseHandle(hProc);
    return ok;
}

void hSysUlocker(){
	HKEY hKey;
	RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",0, KEY_SET_VALUE, &hKey);
	RegDeleteValueA(hKey, "DisableCMD");
	RegCloseKey(hKey);
	system("cmd /c reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoFolderOptions /f");
	system("cmd /c reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableTaskMgr /f");
	system("cmd /c reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableRegistryTools /f");
	system("cmd /c reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v DisableCMD /f");
	system("cmd /c reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoTrayContextMenu /f");
	system("cmd /c reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v DisallowLock /f");
	system("cmd /c reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoLogOff /f");
}
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdLine, int show)
{
    (void)hInst;
    (void)hPrev;
    (void)cmdLine;
    (void)show;
    hSysUlocker();
    const wchar_t *targetExe = L"zmserv.exe";

    if (!EnableDebugPrivilege())
    {
        MessageBoxW(NULL,
            L"启用 SeDebugPrivilege 失败！\n请以管理员身份运行！",
            L"错误",
            MB_ICONERROR);
        return 1;
    }

    DWORD rootPid = FindRootPid(targetExe);
    if (rootPid == 0)
    {
        MessageBoxW(NULL,
            L"未找到 zmserv.exe\n当前机房管理助手可能尚未加载完毕，提前结束可能会导致系统蓝屏\n(原因是新版机房管理助手调用了SeDebugPrivilege将自己设为系统进程，请不要尝试在任务管理器中结束)。\n \n也有可能你已经结束了机房管理助手，只是右下角托盘图标未刷新，你可以将鼠标放上去验证。\n \n目前已为你解除文件夹选项等系统限制，如果你有能力，\n你已经可以在资源管理器中查看机房管理助手的目录并执行一些操作了。",
            L"悲/喜报 - By Hyrvex",
            MB_ICONINFORMATION);
        return 1;
    }

    AddPid(rootPid);
    CollectChildren(rootPid);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NtSetInformationProcess pNtSetInfo =
        (PFN_NtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");

    if (!pNtSetInfo)
    {
        MessageBoxW(NULL,
            L"获取 NtSetInformationProcess 地址失败！",
            L"错误",
            MB_ICONERROR);
        return 1;
    }

    BOOL allClear = TRUE;
    for (int i = 0; i < pidCount; i++)
    {
        if (!ClearBreakFlag(pidList[i], pNtSetInfo))
            allClear = FALSE;
    }

    if (allClear)
    {
        /*MessageBoxW(NULL,
            L"全部标记清除成功！准备终止进程！",
            L"阶段 1",
            MB_OK);*/
    }
    else
    {
        MessageBoxW(NULL,
            L"部分进程标记清除失败！继续终止存在蓝屏风险！",
            L"警告",
            MB_ICONWARNING);
    }

    BOOL allTerm = TRUE;
    for (int i = 0; i < pidCount; i++)
    {
        if (!TerminateTarget(pidList[i]))
            allTerm = FALSE;
    }

    if (allTerm)
    {
        /*MessageBoxW(NULL,
            L"所有进程已尝试终止！",
            L"完成",
            MB_ICONINFORMATION);*/
    }
    else
    {
        /*MessageBoxW(NULL,
            L"部分进程终止失败！",
            L"结果",
            MB_ICONWARNING);*/
    }
    //Sleep(1000);
    hSysUlocker();
	system("taskkill /F /FI \"USERNAME eq %USERNAME%\"");
	Sleep(1000);
	system("start explorer.exe");
	//MessageBoxW(NULL,L"成功杀死机房管理助手主进程，现在你可以继续进行其他操作了，部分程序可能需要重新打开。",L"成功 - By Hyrvex",MB_ICONINFORMATION);
    return 0;
}
