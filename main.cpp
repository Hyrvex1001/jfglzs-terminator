#define WINVER 0x0601
#define _WIN32_WINNT 0x0601
#define WM_MY_ADMIN_MSG (WM_USER + 100)
#define PROCESS_TERMINATE 0x0001
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <cstring>
#include <aclapi.h>

#ifndef NTAPI
#define NTAPI __stdcall
#endif
typedef LONG NTSTATUS;
#ifndef S_OK
#define S_OK ((HRESULT)0L)
#endif

#define ARRAYSIZE(arr)  (sizeof(arr)/sizeof((arr)[0]))
#define KILL_FORCE   1
#define KILL_DEFAULT 2

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

// fltuser.h--------------------------------------------------------------------

typedef HRESULT (WINAPI *PFN_FilterConnectCommunicationPort)(
    LPCWSTR, DWORD, LPCVOID, WORD, LPSECURITY_ATTRIBUTES, HANDLE*);
typedef HRESULT (WINAPI *PFN_FilterSendMessage)(HANDLE, LPVOID, DWORD, LPVOID, DWORD, LPDWORD);

static PFN_FilterConnectCommunicationPort pFilterConnect = NULL;
static PFN_FilterSendMessage          pFilterSend    = NULL;
static HMODULE                         hFltLib        = NULL;

static void LoadFltLib()
{
    if(hFltLib) return;
    hFltLib = LoadLibraryA("FltLib.dll");
    if(hFltLib)
    {
        pFilterConnect = (PFN_FilterConnectCommunicationPort)GetProcAddress(hFltLib, "FilterConnectCommunicationPort");
        pFilterSend = (PFN_FilterSendMessage)GetProcAddress(hFltLib, "FilterSendMessage");
    }
}

DWORD GetProcessIDFromName(LPCSTR szName)
{
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if(Process32First(hSnap, &pe32))
        {
            do
            {
                if(_stricmp(pe32.szExeFile, szName) == 0)
                {
                    pid = pe32.th32ProcessID;
                    break;
                }
            }while(Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return pid;
}

BOOL KillProcess(DWORD dwProcessID, int way)
{
    if(dwProcessID == 0) return FALSE;
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessID);
    if(!hProc) return FALSE;
    BOOL ret = TerminateProcess(hProc, 0);
    CloseHandle(hProc);
    return ret;
}

//--------------------------------------------------------------------

// isAdmin------------------------------------------------------------

BOOL IsAdmin() {
    BOOL bIsAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdminSID = NULL;

    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pAdminSID))
    {
        CheckTokenMembership(NULL, pAdminSID, &bIsAdmin);
        FreeSid(pAdminSID);
    }
    return bIsAdmin;
}

BOOL ElevateSelf() {
    TCHAR szPath[MAX_PATH];
    if (GetModuleFileName(NULL, szPath, MAX_PATH) == 0) {
        return FALSE;
    }
    SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };
    sei.lpVerb = TEXT("runas");
    sei.lpFile = szPath;
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteEx(&sei);
}

//--------------------------------------------------------------------

// ProcessProtector---------------------------------------------------

BOOL EnableSelfProcessGuard(void)
{
    HANDLE hProcess = GetCurrentProcess();
    PACL pOldDACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    DWORD err = GetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL,
        &pOldDACL, NULL, &pSD);
    if (err != ERROR_SUCCESS)
    {
        if(pSD) LocalFree(pSD);
        return FALSE;
    }

    EXPLICIT_ACCESSA ea = {0};
    ea.grfAccessPermissions = PROCESS_TERMINATE;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;

    SID_IDENTIFIER_AUTHORITY sia = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryone = NULL;
    if (!AllocateAndInitializeSid(&sia, 1, SECURITY_WORLD_RID,
        0,0,0,0,0,0,0, &pEveryone))
    {
        LocalFree(pSD);
        return FALSE;
    }

    ea.Trustee.ptstrName = (LPSTR)pEveryone;
    PACL pNewDACL = NULL;

    DWORD err2 = SetEntriesInAclA(1, &ea, pOldDACL, &pNewDACL);
    FreeSid(pEveryone);
    LocalFree(pSD);

    if(err2 != ERROR_SUCCESS)
    {
        return FALSE;
    }

    DWORD err3 = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
    LocalFree(pNewDACL);

    return (err3 == ERROR_SUCCESS);
}

BOOL DisableSelfProcessGuard(void)
{
    HANDLE hProcess = GetCurrentProcess();
    PSID pEveryone = NULL;
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_WORLD_SID_AUTHORITY;

    if (!AllocateAndInitializeSid(&sia, 1, SECURITY_WORLD_RID,
        0,0,0,0,0,0,0, &pEveryone))
    {
        return FALSE;
    }

    EXPLICIT_ACCESSA ea2 = {0};
    ea2.grfAccessPermissions = PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION |
                               SYNCHRONIZE | READ_CONTROL;
    ea2.grfAccessMode = SET_ACCESS;
    ea2.grfInheritance = NO_INHERITANCE;
    ea2.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea2.Trustee.ptstrName = (LPSTR)pEveryone;

    PACL pNewDACL = NULL;
    DWORD err = SetEntriesInAclA(1, &ea2, NULL, &pNewDACL);
    FreeSid(pEveryone);

    if(err != ERROR_SUCCESS)
    {
        return FALSE;
    }

    DWORD err2 = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
    LocalFree(pNewDACL);

    return (err2 == ERROR_SUCCESS);
}

//--------------------------------------------------------------------

// Unlocker-------------------------------------------------------------

void UnlockSystemPrograms()
{
    HKEY retKey;
    LONG ret;
    DWORD value = 0, out = 0, cb;
    char szPath[BUFSIZ];

    typedef struct{
        LPCSTR regPath;
        struct { LPCSTR valName; } items[16];
        int itemCnt;
    } RegTask;

    RegTask hkcuTasks[] =
    {
        {"SOFTWARE\\Policies\\Microsoft\\Windows\\System", {{"DisableCMD"}},1},
        {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            {{"DisableRegistryTools"},{"DisableTaskMgr"},{"DisableLockWorkstation"},{"DisableChangePassword"},{"DisableSwitchUserOption"}},5},
        {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            {{"NoRun"},{"RestrictRun"},{"NoLogOff"},{"StartMenuLogOff"},{"NoTrayContextMenu"},{"Hidden"},{"NoFolderOptions"}},7},
        {"SOFTWARE\\Policies\\Microsoft\\MMC",{{"RestrictToPermittedSnapins"}},1},
        {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3",{{"1803"},{"2200"}},2}
    };

    for(size_t ti=0;ti<ARRAYSIZE(hkcuTasks);ti++)
    {
        RegTask* p = &hkcuTasks[ti];
        ret = RegOpenKeyExA(HKEY_CURRENT_USER, p->regPath,0,KEY_QUERY_VALUE|KEY_SET_VALUE,&retKey);
        if(ret!=ERROR_SUCCESS) continue;
        for(int i=0;i<p->itemCnt;i++)
        {
            cb=sizeof(DWORD);
            ret=RegQueryValueExA(retKey,p->items[i].valName,0,NULL,(BYTE*)&out,&cb);
            if(ret==ERROR_SUCCESS && out!=0)
                RegSetValueExA(retKey,p->items[i].valName,0,REG_DWORD,(CONST BYTE*)&value,sizeof(DWORD));
        }
        RegCloseKey(retKey);
    }

    RegTask hklmUsbTasks[] =
    {
        {"SYSTEM\\CurrentControlSet\\Services\\usbstor",{{"Start"}},1},
        {"SYSTEM\\ControlSet001\\Services\\usbstor",{{"Start"}},1},
        {"SYSTEM\\ControlSet002\\Services\\usbstor",{{"Start"}},1},
        {"SYSTEM\\ControlSet003\\Services\\usbstor",{{"Start"}},1},
    };
    value = 3;
    for(size_t ti=0;ti<ARRAYSIZE(hklmUsbTasks);ti++)
    {
        RegTask* p = &hklmUsbTasks[ti];
        ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, p->regPath,0,KEY_QUERY_VALUE|KEY_SET_VALUE,&retKey);
        if(ret!=ERROR_SUCCESS) continue;
        cb=sizeof(DWORD);
        ret=RegQueryValueExA(retKey,p->items[0].valName,0,NULL,(BYTE*)&out,&cb);
        if(ret==ERROR_SUCCESS && out==4)
            RegSetValueExA(retKey,p->items[0].valName,0,REG_DWORD,(CONST BYTE*)&value,sizeof(DWORD));
        RegCloseKey(retKey);
    }

    const char* images[]={
        "taskkill.exe","ntsd.exe","tasklist.exe","sethc.exe","sidebar.exe",
        "Chess.exe","FreeCell.exe","Hearts.exe","Minesweeper.exe","PurblePlace.exe",
        "Mahjong.exe","SpiderSolitaire.exe","bckgzm.exe","chkrzm.exe","shvlzm.exe",
        "Solitaire.exe","winmine.exe","Magnify.exe","QQPCTray.exe"
    };
    for(size_t i=0;i<ARRAYSIZE(images);i++)
    {
        sprintf(szPath,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s",images[i]);
        ret=RegOpenKeyExA(HKEY_LOCAL_MACHINE,szPath,0,KEY_SET_VALUE,&retKey);
        if(ret==ERROR_SUCCESS){
            RegDeleteValueA(retKey,"debugger");
            RegCloseKey(retKey);
        }
    }

    typedef struct{
        LPCSTR regPath;
        struct { LPCSTR valName; } items[16];
        int itemCnt;
    } RegDelTask;

    RegDelTask delTasks[]=
    {
        {"SOFTWARE\\Policies\\Google\\Chrome",{{"AllowDinosaurEasterEgg"},{"DownloadRestrictions"},{"SaveAs"},{"DeveloperToolsAvailability"}},4},
        {"SOFTWARE\\Policies\\Microsoft\\Edge",{{"AllowSurfGame"},{"WebWidgetAllowed"},{"DownloadRestrictions"},{"SaveAs"},{"DeveloperToolsAvailability"}},5},
        {"SOFTWARE\\Policies\\Mozilla\\Firefox",{{"DisableDownloads"},{"BlockAboutDownloads"},{"DeveloperToolsAvailability"}},3},
        {"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",{{"AllowMultipleTSSessions"}},1},
        {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",{{"HideFastUserSwitching"}},1},
        {"SOFTWARE\\Policies\\Microsoft\\WindowsStore",{{"RemoveWindowsStore"}},1}
    };

    for(size_t ti=0;ti<ARRAYSIZE(delTasks);ti++)
    {
        RegDelTask* p=&delTasks[ti];
        ret=RegOpenKeyExA(HKEY_LOCAL_MACHINE,p->regPath,0,KEY_SET_VALUE,&retKey);
        if(ret!=ERROR_SUCCESS) continue;
        for(int i=0;i<p->itemCnt;i++)
            RegDeleteValueA(retKey,p->items[i].valName);
        RegCloseKey(retKey);
    }

    ret=RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions",0,KEY_SET_VALUE,&retKey);
    if(ret==ERROR_SUCCESS){ RegDeleteValueA(retKey,"NoBrowserSaveAs"); RegCloseKey(retKey); }

    ret=RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",0,KEY_SET_VALUE,&retKey);
    if(ret==ERROR_SUCCESS){ RegDeleteValueA(retKey,"ShowTaskViewButton"); RegCloseKey(retKey); }

    ret=RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout",0,KEY_SET_VALUE,&retKey);
    if(ret==ERROR_SUCCESS){ RegDeleteValueA(retKey,"Scancode Map"); RegCloseKey(retKey); }

    const char* path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    char tempPath[MAX_PATH];
    sprintf(tempPath,"%s.tmp",path);

    bool bHandled = false;
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hTemp = CreateFileA(tempPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile != INVALID_HANDLE_VALUE && hTemp != INVALID_HANDLE_VALUE)
    {
        char buf[4096];
        DWORD read;
        char line[2048];
        memset(line,0,sizeof(line));
        int linePos=0;
        while(ReadFile(hFile, buf, sizeof(buf), &read, NULL) && read>0)
        {
            for(DWORD i=0;i<read;i++)
            {
                if(buf[i]=='\n')
                {
                    line[linePos] = 0;
                    if(strstr(line,"127.0.0.1")!=line || strspn(line," \t")<strstr(line,"127.0.0.1")-line)
                    {
                        strcat(line,"\r\n");
                        DWORD wr;
                        WriteFile(hTemp, line, (DWORD)strlen(line), &wr, NULL);
                    }else{
                        bHandled = true;
                    }
                    memset(line,0,sizeof(line));
                    linePos=0;
                }else{
                    if(linePos < (int)sizeof(line)-2)
                        line[linePos++] = buf[i];
                }
            }
        }
        if(linePos>0)
        {
            line[linePos]=0;
            if(strstr(line,"127.0.0.1")!=line || strspn(line," \t")<strstr(line,"127.0.0.1")-line)
            {
                DWORD wr;
                WriteFile(hTemp, line, (DWORD)strlen(line), &wr, NULL);
            }else bHandled=true;
        }
        CloseHandle(hFile);
        CloseHandle(hTemp);
        SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
        DeleteFileA(path);
        if(bHandled) MoveFileA(tempPath, path);
    }
    printf("[Debug]注册表解禁完成\n");
}

void RemoveUSBRestrictions()
{
    LoadFltLib();
    if(pFilterConnect && pFilterSend)
    {
        HANDLE hPort = NULL;
        HRESULT hr = pFilterConnect(L"\\TDFileFilterPort",0,NULL,0,NULL,&hPort);
        if(SUCCEEDED(hr) && hPort != NULL)
        {
            int lpInBuffer[4]={8,0,0,0};
            pFilterSend(hPort, lpInBuffer,16,NULL,0,NULL);
            CloseHandle(hPort);
        }
    }

    SC_HANDLE sc = OpenSCManagerA(NULL,NULL,SC_MANAGER_CONNECT);
    if(sc != NULL)
    {
        SC_HANDLE hFilt = OpenServiceA(sc,"TDFileFilter", SERVICE_STOP|DELETE);
        SERVICE_STATUS ss={0};
        if(hFilt != NULL)
        {
            ControlService(hFilt,SERVICE_CONTROL_STOP,&ss);
            DeleteService(hFilt);
            CloseServiceHandle(hFilt);
        }
        CloseServiceHandle(sc);
    }
    printf("[Debug]U盘解禁完成\n");
}

void RemoveNetworkRestrictions()
{
    HANDLE hNetFilter = CreateFileA("\\\\.\\TDNetFilter", GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING,0,NULL);
    if(hNetFilter != INVALID_HANDLE_VALUE)
    {
        DWORD junk;
        DeviceIoControl(hNetFilter,0x120014,NULL,0,NULL,0,&junk,NULL);
        CloseHandle(hNetFilter);
    }

    KillProcess(GetProcessIDFromName("MasterHelper.exe"), KILL_DEFAULT);
    KillProcess(GetProcessIDFromName("GATESRV.exe"), KILL_DEFAULT);

    SC_HANDLE sc = OpenSCManagerA(NULL,NULL,SC_MANAGER_CONNECT);
    if(sc != NULL)
    {
        SC_HANDLE hFilt = OpenServiceA(sc,"TDNetFilter", SERVICE_STOP|DELETE);
        SERVICE_STATUS ss={0};
        if(hFilt != NULL)
        {
            ControlService(hFilt,SERVICE_CONTROL_STOP,&ss);
            DeleteService(hFilt);
            CloseServiceHandle(hFilt);
        }
        CloseServiceHandle(sc);
    }
    printf("[Debug]网络解禁完成\n");
}

void SetUacMaxLevel()
{
    HKEY hKey;
	if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
	    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
	    0,KEY_WRITE,&hKey)==ERROR_SUCCESS)
	{
	    DWORD v;
	    v=1; RegSetValueExA(hKey,"EnableLUA",0,REG_DWORD,(BYTE*)&v,sizeof(DWORD));
	    v=2; RegSetValueExA(hKey,"ConsentPromptBehaviorAdmin",0,REG_DWORD,(BYTE*)&v,sizeof(DWORD));
	    v=3; RegSetValueExA(hKey,"ConsentPromptBehaviorUser",0,REG_DWORD,(BYTE*)&v,sizeof(DWORD));
	    v=1; RegSetValueExA(hKey,"PromptOnSecureDesktop",0,REG_DWORD,(BYTE*)&v,sizeof(DWORD));
	    v=1; RegSetValueExA(hKey,"FilterAdministratorToken",0,REG_DWORD,(BYTE*)&v,sizeof(DWORD));
	    RegCloseKey(hKey);
	}
    printf("[Debug]UAC已开启\n");
}

//------------------------------------------------
void hSysUlocker(){
	UnlockSystemPrograms();
	RemoveUSBRestrictions();
	RemoveNetworkRestrictions();
	SetUacMaxLevel();
	printf("\n[Debug]全部操作执行完毕\n");
	/*old
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
	*/
}
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdLine, int show)
{
    (void)hInst;
    (void)hPrev;
    (void)cmdLine;
    (void)show;
    
    EnableSelfProcessGuard(); // 开启守护(作用不大)
    hSysUlocker();
    
    if (!IsAdmin())
	{
	    int nRet = MessageBoxW(NULL,
	        L"当前未使用管理员权限运行，部分操作可能会执行失败，\n是否尝试提权？",
	        L"警告",
	        MB_YESNO | MB_ICONQUESTION | MB_TOPMOST);
	
	    if(nRet == IDYES)
	    {
	        ElevateSelf();
	        return 1; 
	    }
	}
	
	hSysUlocker();
    const wchar_t *targetExe = L"zmserv.exe";

    if (!EnableDebugPrivilege())
    {
     int nRet = MessageBoxW(NULL,
	        L"启用 SeDebugPrivilege 失败！\n无管理员权限将无法继续操作! \n \n是否立即尝试提权？",
			L"错误",
	        MB_YESNO | MB_ICONERROR | MB_TOPMOST);
	
	    if(nRet == IDYES)
	    {
	        ElevateSelf();
	    }
	    return 1;
    }

    DWORD rootPid = FindRootPid(targetExe);
    if (rootPid == 0)
    {
        int nRet = MessageBoxW(NULL,
            L"未找到 zmserv.exe\n当前机房管理助手可能尚未加载完毕，提前结束可能会导致系统蓝屏\n(原因是新版机房管理助手调用了SeDebugPrivilege将自己设为系统进程，请不要尝试在任务管理器中结束)。\n \n也有可能你已经结束了机房管理助手，只是右下角托盘图标未刷新，你可以将鼠标放上去验证。\n \n你想尝试现在立刻结束掉机房管理助手的其他进程吗？\n该操作具有风险，请谨慎考虑。",
            L"悲/喜报 - By Hyrvex",
            MB_YESNO | MB_ICONINFORMATION | MB_TOPMOST);
        if(nRet == IDNO)
		{
		MessageBoxW(NULL,
		    L"目前已为你解除文件夹选项等系统限制，如果你有能力，\n你已经可以在资源管理器中查看机房管理助手的目录并执行一些操作了。",
		    L"悲/喜报 - By Hyrvex",
		    MB_ICONINFORMATION | MB_TOPMOST);
		return 1;
		}
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
            MB_ICONERROR | MB_TOPMOST);
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
        /*MessageBoxW(NULL,
            L"部分进程标记清除失败！继续终止存在蓝屏风险！",
            L"警告",
            MB_ICONWARNING);*/
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
	DisableSelfProcessGuard();
    return 0;
}
