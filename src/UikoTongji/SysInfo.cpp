#include "stdafx.h"
#include "SysInfo.h"

#include <float.h>
#include <atlbase.h>
#include <atlconv.h>
#include <atlstr.h>
#include <atlcoll.h>
//#include <afxtempl.h>
#include <winperf.h>

#include "MD5.h"

//AES
#include "AES.h"

//PostData
#include <WinInet.h>
#pragma comment( lib, "wininet.lib")

//系统版本
#include <WinVer.h>
#pragma comment (lib, "Version.lib")

/****获取操作系统版本，Service pack版本、系统类型****/
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#pragma comment(lib, "User32.lib")  
#define BUFSIZE 256
typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
typedef BOOL (WINAPI *PGPI)(DWORD, DWORD, DWORD, DWORD, PDWORD);

//获取MAC地址
#include "Nb30.h"
#pragma comment (lib,"netapi32.lib")
typedef struct tagMAC_ADDRESS
{
    BYTE b1,b2,b3,b4,b5,b6;
}MAC_ADDRESS,*LPMAC_ADDRESS;
typedef struct tagASTAT 
{ 
    ADAPTER_STATUS adapt; 
    NAME_BUFFER    NameBuff [30]; 
}ASTAT,*LPASTAT; 

//ANSI转unicode
wchar_t* AnsiToUnicode(char *str)
{
	DWORD dwNum = MultiByteToWideChar (CP_ACP, 0, str, -1, NULL, 0);
	wchar_t *pwText;
	pwText = new wchar_t[dwNum];
	if(!pwText)
	{
		delete []pwText;
	}
	MultiByteToWideChar (CP_ACP, 0, str, -1, pwText, dwNum);
    return pwText;
    delete []pwText;
}
//Unicode转ansi
char* UnicodeToAnsi(wchar_t *str)
{
    //wchar_t wText[20] = {L"宽字符转换实例!"};
    DWORD dwNum = WideCharToMultiByte(CP_OEMCP,NULL,str,-1,NULL,0,NULL,FALSE);
    char *psText;
    psText = new char[dwNum];
    if(!psText)
    {
        delete []psText;
    }
    WideCharToMultiByte (CP_OEMCP,NULL,str,-1,psText,dwNum,NULL,FALSE);
    return psText;
    delete []psText;
}
 
SysInfo::SysInfo(void){ }
SysInfo::~SysInfo(void){ }

/****获取操作系统版本，Service pack版本、系统类型****/
BOOL SysInfo::GetOSDisplayString( LPTSTR pszOS)
{
   OSVERSIONINFOEX osvi;
   SYSTEM_INFO si;
   PGNSI pGNSI;
   PGPI pGPI;
   BOOL bOsVersionInfoEx;
   DWORD dwType;

   ZeroMemory(&si, sizeof(SYSTEM_INFO));
   ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

   osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
   bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO*) &osvi);
   
   GetNtVersionNumbers(osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);

   if(bOsVersionInfoEx == NULL ) return 1;

   // Call GetNativeSystemInfo if supported or GetSystemInfo otherwise.
   pGNSI = (PGNSI) GetProcAddress( GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
   if(NULL != pGNSI) 
       pGNSI(&si);
   else GetSystemInfo(&si);

   if ( VER_PLATFORM_WIN32_NT == osvi.dwPlatformId && osvi.dwMajorVersion > 4 )
   {
      //StringCchCopy(pszOS, BUFSIZE, TEXT("Microsoft "));
      StringCchCopy(pszOS, BUFSIZE, TEXT(""));
      // Test for the specific product.

      if ( osvi.dwMajorVersion == 6 || osvi.dwMajorVersion == 10 )
      {
          if ( osvi.dwMajorVersion == 10 )
          {
             if( osvi.dwMinorVersion == 0 )
             {
                if( osvi.wProductType == VER_NT_WORKSTATION )
                    StringCchCat(pszOS, BUFSIZE, TEXT("Win10-"));
                else StringCchCat(pszOS, BUFSIZE, TEXT("WinSer2016-" ));
             }
          }
          if ( osvi.dwMajorVersion == 6 )
          {
             if( osvi.dwMinorVersion == 0 )
             {
                if( osvi.wProductType == VER_NT_WORKSTATION )
                    StringCchCat(pszOS, BUFSIZE, TEXT("Vista-"));
                else StringCchCat(pszOS, BUFSIZE, TEXT("WinSer2008-" ));
             }
             else if ( osvi.dwMinorVersion == 1 )
             {
                if( osvi.wProductType == VER_NT_WORKSTATION )
                    StringCchCat(pszOS, BUFSIZE, TEXT("Win7-"));
                else StringCchCat(pszOS, BUFSIZE, TEXT("WinSer2008R2-" ));
             }
             else if ( osvi.dwMinorVersion == 2 )
             {
                if( osvi.wProductType == VER_NT_WORKSTATION )
                    StringCchCat(pszOS, BUFSIZE, TEXT("Win8-"));
                else StringCchCat(pszOS, BUFSIZE, TEXT("WinSer2012-" ));
             }
             else if ( osvi.dwMinorVersion == 3 )
             {
                if( osvi.wProductType == VER_NT_WORKSTATION )
                    StringCchCat(pszOS, BUFSIZE, TEXT("Win8.1-"));
                else StringCchCat(pszOS, BUFSIZE, TEXT("WinSer2012R2-" ));
             }
             else if ( osvi.dwMinorVersion == 4 )
             {
                if( osvi.wProductType == VER_NT_WORKSTATION )
                    StringCchCat(pszOS, BUFSIZE, TEXT("Win10-"));
                else StringCchCat(pszOS, BUFSIZE, TEXT("WinSer2016-" ));
             }
          }
         pGPI = (PGPI) GetProcAddress( GetModuleHandle(TEXT("kernel32.dll")), "GetProductInfo");
         pGPI( osvi.dwMajorVersion, osvi.dwMinorVersion, 0, 0, &dwType );

         switch( dwType )
         {
            case PRODUCT_ULTIMATE:
               StringCchCat(pszOS, BUFSIZE, TEXT("Ultimate" ));
               break;
            //case PRODUCT_PROFESSIONAL:
            //   StringCchCat(pszOS, BUFSIZE, TEXT("Professional" ));
            //   break;
            case PRODUCT_HOME_PREMIUM:
               StringCchCat(pszOS, BUFSIZE, TEXT("Home Premium" ));
               break;
            case PRODUCT_HOME_BASIC:
               StringCchCat(pszOS, BUFSIZE, TEXT("Home Basic" ));
               break;
            case PRODUCT_ENTERPRISE:
               StringCchCat(pszOS, BUFSIZE, TEXT("Enterprise" ));
               break;
            case PRODUCT_BUSINESS:
               StringCchCat(pszOS, BUFSIZE, TEXT("Business" ));
               break;
            case PRODUCT_STARTER:
               StringCchCat(pszOS, BUFSIZE, TEXT("Starter" ));
               break;
            case PRODUCT_CLUSTER_SERVER:
               StringCchCat(pszOS, BUFSIZE, TEXT("Cluster Server" ));
               break;
            case PRODUCT_DATACENTER_SERVER:
               StringCchCat(pszOS, BUFSIZE, TEXT("Datacenter" ));
               break;
            case PRODUCT_DATACENTER_SERVER_CORE:
               StringCchCat(pszOS, BUFSIZE, TEXT("Datacenter (core installation)" ));
               break;
            case PRODUCT_ENTERPRISE_SERVER:
               StringCchCat(pszOS, BUFSIZE, TEXT("Enterprise" ));
               break;
            case PRODUCT_ENTERPRISE_SERVER_CORE:
               StringCchCat(pszOS, BUFSIZE, TEXT("Enterprise (core installation)" ));
               break;
            case PRODUCT_ENTERPRISE_SERVER_IA64:
               StringCchCat(pszOS, BUFSIZE, TEXT("Enterprise for Itanium-based Systems" ));
               break;
            case PRODUCT_SMALLBUSINESS_SERVER:
               StringCchCat(pszOS, BUFSIZE, TEXT("Small Business Server" ));
               break;
            case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM:
               StringCchCat(pszOS, BUFSIZE, TEXT("Small Business Server Premium Edition" ));
               break;
            case PRODUCT_STANDARD_SERVER:
               StringCchCat(pszOS, BUFSIZE, TEXT("Standard" ));
               break;
            case PRODUCT_STANDARD_SERVER_CORE:
               StringCchCat(pszOS, BUFSIZE, TEXT("Standard (core installation)" ));
               break;
            case PRODUCT_WEB_SERVER:
               StringCchCat(pszOS, BUFSIZE, TEXT("Web Server" ));
               break;
            default:
               StringCchCat(pszOS, BUFSIZE, TEXT("Professional" ));
               break;
         }
      }

      if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2 )
      {
         if( GetSystemMetrics(SM_SERVERR2) )
            StringCchCat(pszOS, BUFSIZE, TEXT( "WinSer2003R2-"));
         else if ( osvi.wSuiteMask & VER_SUITE_STORAGE_SERVER )
            StringCchCat(pszOS, BUFSIZE, TEXT( "Windows Storage Server 2003"));
         //else if ( osvi.wSuiteMask & VER_SUITE_WH_SERVER )
         //   StringCchCat(pszOS, BUFSIZE, TEXT( "Windows Home Server"));
         else if( osvi.wProductType == VER_NT_WORKSTATION && si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
            StringCchCat(pszOS, BUFSIZE, TEXT( "Windows XP Professional x64 Edition"));
         else StringCchCat(pszOS, BUFSIZE, TEXT("WinSer2003-"));

         // Test for the server type.
         if ( osvi.wProductType != VER_NT_WORKSTATION )
         {
            if ( si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 )
            {
                if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                   StringCchCat(pszOS, BUFSIZE, TEXT( "Datacenter Edition for Itanium-based Systems" ));
                else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                   StringCchCat(pszOS, BUFSIZE, TEXT( "Enterprise Edition for Itanium-based Systems" ));
            }
            else if ( si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 )
            {
                if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                   StringCchCat(pszOS, BUFSIZE, TEXT( "Datacenter x64 Edition" ));
                else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                   StringCchCat(pszOS, BUFSIZE, TEXT( "Enterprise x64 Edition" ));
                else StringCchCat(pszOS, BUFSIZE, TEXT( "Standard x64 Edition" ));
            }
            else
            {
                if ( osvi.wSuiteMask & VER_SUITE_COMPUTE_SERVER )
                   StringCchCat(pszOS, BUFSIZE, TEXT( "Compute Cluster Edition" ));
                else if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                   StringCchCat(pszOS, BUFSIZE, TEXT( "Datacenter Edition" ));
                else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                   StringCchCat(pszOS, BUFSIZE, TEXT( "Enterprise Edition" ));
                else if ( osvi.wSuiteMask & VER_SUITE_BLADE )
                   StringCchCat(pszOS, BUFSIZE, TEXT( "Web Edition" ));
                else StringCchCat(pszOS, BUFSIZE, TEXT( "Standard Edition" ));
            }
         }
      }

      if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 )
      {
         StringCchCat(pszOS, BUFSIZE, TEXT("WinXP-"));
         if( osvi.wSuiteMask & VER_SUITE_PERSONAL )
            StringCchCat(pszOS, BUFSIZE, TEXT( "Home Edition" ));
         else StringCchCat(pszOS, BUFSIZE, TEXT( "Professional" ));
      }

      if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0 )
      {
         StringCchCat(pszOS, BUFSIZE, TEXT("Win2000-"));

         if ( osvi.wProductType == VER_NT_WORKSTATION )
         {
            StringCchCat(pszOS, BUFSIZE, TEXT( "Professional" ));
         }
         else 
         {
            if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
               StringCchCat(pszOS, BUFSIZE, TEXT( "Datacenter Server" ));
            else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
               StringCchCat(pszOS, BUFSIZE, TEXT( "Advanced Server" ));
            else StringCchCat(pszOS, BUFSIZE, TEXT( "Server" ));
         }
      }

      // Service Pack
      if( bOsVersionInfoEx )
	  {
		  //将Service Pack 版本保存
		  if(osvi.wServicePackMajor != 0)
		  {
              TCHAR buf[10];
              StringCchPrintf( buf, 80, TEXT("-SP%d"),osvi.wServicePackMajor );
              StringCchCat(pszOS, BUFSIZE, buf);
		  }
      }
      
      // Include service pack (if any) and build number.
      //if( _tcslen(osvi.szCSDVersion) > 0 )
      //{
      //    StringCchCat(pszOS, BUFSIZE, TEXT("-SP") );
      //    StringCchCat(pszOS, BUFSIZE, osvi.szCSDVersion);
      //}
      
      //TCHAR buf[80];
      //StringCchPrintf( buf, 80, TEXT(" (%d.%d.%d)"),osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
      //StringCchCat(pszOS, BUFSIZE, buf);

      if ( osvi.dwMajorVersion >= 6 )
      {
         if ( si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 )
            StringCchCat(pszOS, BUFSIZE, TEXT( "-64" ));
         else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL )
            StringCchCat(pszOS, BUFSIZE, TEXT( "-32" ));
      }
      
      return TRUE; 
   }
   else
   {  
      //printf( "This sample does not support this version of Windows.\n");
      return FALSE;
   }
}
CString SysInfo::GetNtVersionNumbers(DWORD&dwMajorVer, DWORD& dwMinorVer,DWORD& dwBuildNumber)
{
    BOOL bRet= FALSE;
    HMODULE hModNtdll= NULL;
    if (hModNtdll= ::LoadLibraryW(L"ntdll.dll"))
    {
        typedef void (WINAPI *pfRTLGETNTVERSIONNUMBERS)(DWORD*,DWORD*, DWORD*);
        pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers;
        pfRtlGetNtVersionNumbers = (pfRTLGETNTVERSIONNUMBERS)::GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
        if (pfRtlGetNtVersionNumbers)
        {
           pfRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer,&dwBuildNumber);
           dwBuildNumber&= 0x0ffff;
           bRet = TRUE;
        }
 
        ::FreeLibrary(hModNtdll);
        hModNtdll = NULL;
    }
    CString strOSVersion;
    strOSVersion.Format(_T("%d.%d.%d"),dwMajorVer,dwMinorVer,dwBuildNumber);
    return strOSVersion;
}
void SysInfo::GetOSVersion(CString &strOSVersion,CString &strServiceVersion)
{ 

	CString str;
	OSVERSIONINFOEX osvi;
	SYSTEM_INFO si;
	BOOL bOsVersionInfoEx;

	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
	{
		osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
        GetVersionEx ( (OSVERSIONINFO *) &osvi);
	}

    GetNtVersionNumbers(osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    
	GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");

	GetSystemInfo(&si);
	switch (osvi.dwPlatformId)
	{
	case VER_PLATFORM_WIN32_NT:
		if ( osvi.dwMajorVersion == 10 && osvi.dwMinorVersion == 0 )
		{
			if( osvi.wProductType == VER_NT_WORKSTATION )
			{
				str.Format(_T("Windows 10 "));
			}
			else 
			{
				str.Format(_T("Windows Server 2016 "));
			}
		}
		if ( osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 4 )
		{
			if( osvi.wProductType == VER_NT_WORKSTATION )
			{
				str.Format(_T("Windows 10 "));
			}
			else 
			{
				str.Format(_T("Windows Server 2016 "));
			}
		}
		if ( osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 3 )
		{
			if( osvi.wProductType == VER_NT_WORKSTATION )
			{
				str.Format(_T("Windows 8.1 "));
			}
			else 
			{
				str.Format(_T("Windows Server 2012 R2 "));
			}
		}
		if ( osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 2 )
		{
			if( osvi.wProductType == VER_NT_WORKSTATION )
			{
				str.Format(_T("Windows 8 "));
			}
			else 
			{
				str.Format(_T("Windows Server 2012 "));
			}
		}
		if ( osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1 )
		{
			if( osvi.wProductType == VER_NT_WORKSTATION )
			{
				str.Format(_T("Windows 7 "));
			}
			else 
			{
				str.Format(_T("Windows Server 2008 R2 "));
			}
		}
		if ( osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 0 )
		{
			if( osvi.wProductType == VER_NT_WORKSTATION )
			{
				str.Format(_T("Windows Vista "));
			}
			else 
			{
				str.Format(_T("Windows Server 2008 "));
			}
		}
		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2 )
		{
			if( GetSystemMetrics(SM_SERVERR2) )
			{
				str.Format(_T("Windows Server 2003 R2 "));
			}
			else if( osvi.wProductType == VER_NT_WORKSTATION &&
				si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)
			{
				str.Format(_T("Windows XP Professional x64 Edition "));
			}
			else 
			{
				str.Format(_T("Windows Server 2003 "));
			}
		}

		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 )
		{
			str.Format(_T("Windows XP "));
		}
		if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0 )
		{
			str.Format(_T("Windows 2000 "));
        }
		if ( osvi.dwMajorVersion <= 4 )
		{
			str.Format(_T("Windows NT "));
		}

		// Test for specific product on Windows NT 4.0 SP6 and later.
		if( bOsVersionInfoEx )
		{

			//将Service Pack 版本保存
			if(osvi.wServicePackMajor != 0)
			    strServiceVersion.Format(_T("SP%d"),osvi.wServicePackMajor);

			// Test for the workstation type.
			if ( osvi.wProductType == VER_NT_WORKSTATION && si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64)
			{
				if( osvi.dwMajorVersion == 4 )
					str = str + _T("Workstation 4.0");
				else if( osvi.wSuiteMask & VER_SUITE_PERSONAL )
					str = str + _T("Home Edition");
				else 
				    str = str + _T( "Professional");
				    
                //if( osvi.wSuiteMask == VER_SUITE_ENTERPRISE )
                //    str = str + _T("Enterprise ");
                //else if( osvi.wSuiteMask == VER_SUITE_EMBEDDEDNT )
                //    str = str + _T("Embedded ");
                //else if( osvi.wSuiteMask == VER_SUITE_PERSONAL )
                //    str = str + _T("Home ");
                //else 
                //    str = str + _T( "Professional");
			}

			// Test for the server type.
			else if ( osvi.wProductType == VER_NT_SERVER || osvi.wProductType == VER_NT_DOMAIN_CONTROLLER )
			{
				if(osvi.dwMajorVersion==5 && osvi.dwMinorVersion==2)
				{
					if ( si.wProcessorArchitecture ==
						PROCESSOR_ARCHITECTURE_IA64 )
					{
						if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
							str = str + _T("Datacenter Edition for Itanium-based Systems");
						else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
							str = str + _T("Enterprise Edition for Itanium-based Systems");
					}

					else if ( si.wProcessorArchitecture ==
						PROCESSOR_ARCHITECTURE_AMD64 )
					{
						if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
							str = str + _T( "Datacenter x64 Edition ");
						else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
							str = str + _T( "Enterprise x64 Edition ");
						else str = str + _T( "Standard x64 Edition ");
					}

					else
					{
						if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
							str = str + _T( "Datacenter Edition ");
						else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
							str = str + _T( "Enterprise Edition ");
						else if ( osvi.wSuiteMask & VER_SUITE_BLADE )
							str = str + _T( "Web Edition ");
						else str = str + _T( "Standard Edition ");
					}
				}
				else if(osvi.dwMajorVersion==5 && osvi.dwMinorVersion==0)
				{
					if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
						str = str + _T("Datacenter Server ");
					else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
						str = str + _T( "Advanced Server ");
					else str = str + _T( "Server ");
				}
				else  // Windows NT 4.0 
				{
					if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
						str = str + _T ("Server 4.0, Enterprise Edition ");
					else str = str + _T ( "Server 4.0 " );
				}
			}
		}
		// Test for specific product on Windows NT 4.0 SP5 and earlier
		else  
		{
			HKEY hKey;
			TCHAR szProductType[256];
			DWORD dwBufLen=256*sizeof(TCHAR);
			LONG lRet;

			lRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
				_T("SYSTEM\\CurrentControlSet\\Control\\ProductOptions"), 0, KEY_QUERY_VALUE, &hKey );
			if( lRet != ERROR_SUCCESS )
				strOSVersion = str;
				return;

			lRet = RegQueryValueEx( hKey, TEXT("ProductType"),
				NULL, NULL, (LPBYTE) szProductType, &dwBufLen);
			RegCloseKey( hKey );

			if( (lRet != ERROR_SUCCESS) ||
				(dwBufLen > 256*sizeof(TCHAR)) )
				strOSVersion = str;
				return;

			if ( lstrcmpi( TEXT("WINNT"), szProductType) == 0 )
				str = str + _T( "Workstation ");
			if ( lstrcmpi( TEXT("LANMANNT"), szProductType) == 0 )
				str = str + _T( "Server " );
			if ( lstrcmpi( TEXT("SERVERNT"), szProductType) == 0 )
				str = str + _T( "Advanced Server ");
			str.Format(_T( "%d.%d "), osvi.dwMajorVersion, osvi.dwMinorVersion );
		}

		// Display service pack (if any) and build number.

		if( osvi.dwMajorVersion == 4 && lstrcmpi( osvi.szCSDVersion, TEXT("SP6") ) == 0 )
		{ 
			HKEY hKey;
			LONG lRet;
			// Test for SP6 versus SP6a.
			lRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
				_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix\\Q246009"), 0, KEY_QUERY_VALUE, &hKey );
			if( lRet == ERROR_SUCCESS )
				str.Format( _T( "SP6") );//str.Format(_T( "SP6a (Build %d)\n"), osvi.dwBuildNumber & 0xFFFF );         
			else // Windows NT 4.0 prior to SP6a
			{
				_tprintf( TEXT("%s (Build %d)\n"), osvi.szCSDVersion, osvi.dwBuildNumber & 0xFFFF);
			}
			RegCloseKey( hKey );
		}
		else // not Windows NT 4.0 
		{
			_tprintf( TEXT("%s (Build %d)\n"),
				osvi.szCSDVersion,
				osvi.dwBuildNumber & 0xFFFF);
		}

		break;

		// Test for the Windows Me/98/95.
	case VER_PLATFORM_WIN32_WINDOWS:

		if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 0)
		{
			str.Format(_T("Microsoft Windows 95 "));
			if (osvi.szCSDVersion[1]=='C' || osvi.szCSDVersion[1]=='B')
				str = str + _T("OSR2 ");
		} 

		if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 10)
		{
			str.Format(_T("Microsoft Windows 98 "));
			if ( osvi.szCSDVersion[1]=='A' || osvi.szCSDVersion[1]=='B')
				str = str + _T("SE ");
		} 
		if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 90)
		{
			str.Format(_T("Microsoft Windows Millennium Edition\n"));
		} 
		break;

	case VER_PLATFORM_WIN32s:
		str.Format(_T("Microsoft Win32s\n"));
		break;
	default:
		break;
	}

	strOSVersion = str;
}
/****获取操作系统位数****/
BOOL SysInfo::IsWow64() 
{ 
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL); 
	LPFN_ISWOW64PROCESS fnIsWow64Process; 
	BOOL bIsWow64 = FALSE; 
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( GetModuleHandle(_T("kernel32")),"IsWow64Process"); 
	if (NULL != fnIsWow64Process) 
	{ 
		fnIsWow64Process(GetCurrentProcess(),&bIsWow64);
	} 
	return bIsWow64; 
} 
/****获取用户名****/
CString SysInfo::GetUserInfo()
{
    CString csUserName;
    DWORD size=0;
    if(!GetUserName(NULL, &size))
    {
        TCHAR *name = new TCHAR[size];
        if(GetUserName(name, &size))
        {
            csUserName.Format(_T("%s"), name);
        }
        delete [] name;
    }
    else
    {
        csUserName.Format(_T("%d"), GetLastError());
    }
    return csUserName;
}
/****获取计算机名****/
CString SysInfo::GetHostInfo()
{
    CString csHostName;
    DWORD size=0;
    if (!GetComputerNameEx((COMPUTER_NAME_FORMAT)1, NULL, &size))
    {
        TCHAR *name = new TCHAR[size];
        if(GetComputerNameEx((COMPUTER_NAME_FORMAT)1, name, &size))
        {
            csHostName.Format(_T("%s"), name);
        }
        delete [] name;
    }
    else
    {
        csHostName.Format(_T("%d"), GetLastError());
    }
    return csHostName;
}
/****获取网卡MAC地址****/                       //网卡地址1 精准
unsigned char GetAddressByIndex(int lana_num, ASTAT &Adapter)
{
	NCB ncb; 
	unsigned char uRetCode; 
	memset(&ncb, 0, sizeof(ncb) ); 
	ncb.ncb_command = NCBRESET; 
	ncb.ncb_lana_num = (unsigned char)lana_num; 
	//指定网卡号,首先对选定的网卡发送一个NCBRESET命令,以便进行初始化 
	uRetCode = Netbios(&ncb ); 
	memset(&ncb, 0, sizeof(ncb) ); 
	ncb.ncb_command = NCBASTAT; 
	ncb.ncb_lana_num = (unsigned char)lana_num;   //指定网卡号 
	//strcpy((char *)ncb.ncb_callname,"*      " ); 
	strcpy_s((char *)ncb.ncb_callname, 16, "*      " ); 
	ncb.ncb_buffer = (unsigned char *)&Adapter; 
	//指定返回的信息存放的变量 
	ncb.ncb_length = sizeof(Adapter); 
	//接着,可以发送NCBASTAT命令以获取网卡的信息 
	uRetCode = Netbios(&ncb ); 
	return uRetCode;
} 

int GetMACAddr(LPMAC_ADDRESS pMacAddr)
{
	NCB ncb; 
	UCHAR uRetCode;
	int num = 0;
	LANA_ENUM lana_enum; 
	memset(&ncb, 0, sizeof(ncb) ); 
	ncb.ncb_command = NCBENUM; 
	ncb.ncb_buffer = (unsigned char *)&lana_enum; 
	ncb.ncb_length = sizeof(lana_enum); 
	////向网卡发送NCBENUM命令,以获取当前机器的网卡信息,如有多少个网卡
	////每张网卡的编号等 
	uRetCode = Netbios(&ncb);
	if (uRetCode == 0) 
	{
		num = lana_enum.length;
		//对每一张网卡,以其网卡编号为输入编号,获取其MAC地址 
		for (int i = 0; i < num; i++)
		{
			ASTAT Adapter;
			if(GetAddressByIndex(lana_enum.lana[i],Adapter) == 0)
			{
				pMacAddr[i].b1 = Adapter.adapt.adapter_address[0];
				pMacAddr[i].b2 = Adapter.adapt.adapter_address[1];
				pMacAddr[i].b3 = Adapter.adapt.adapter_address[2];
				pMacAddr[i].b4 = Adapter.adapt.adapter_address[3];
				pMacAddr[i].b5 = Adapter.adapt.adapter_address[4];
				pMacAddr[i].b6 = Adapter.adapt.adapter_address[5];
			}
		}
	}
	return num;
}
CString SysInfo::GetMacAddress()
{
	MAC_ADDRESS m_MacAddr[10];        // 比如最多10个网卡
	int n = GetMACAddr(m_MacAddr);    // 获得网卡数量

#ifdef _UNICODE
    TCHAR szAddr[128] = _T("");
    swprintf_s(szAddr, _T("%02x-%02x-%02x-%02x-%02x-%02x"),
        m_MacAddr[0].b1,
        m_MacAddr[0].b2,
        m_MacAddr[0].b3,
        m_MacAddr[0].b4,
        m_MacAddr[0].b5,
        m_MacAddr[0].b6);
#else
    TCHAR szAddr[128] = "";
    sprintf_s(szAddr, _T("%02x-%02x-%02x-%02x-%02x-%02x"),
        m_MacAddr[0].b1,
        m_MacAddr[0].b2,
        m_MacAddr[0].b3,
        m_MacAddr[0].b4,
        m_MacAddr[0].b5,
        m_MacAddr[0].b6);
#endif
	_tcsupr_s(szAddr);
	
    //CString szAddr;
    //szAddr.Format(_T("%02x-%02x-%02x-%02x-%02x-%02x"),
    //    m_MacAddr[0].b1,
    //    m_MacAddr[0].b2,
    //    m_MacAddr[0].b3,
    //    m_MacAddr[0].b4,
    //    m_MacAddr[0].b5,
    //    m_MacAddr[0].b6);
    
	return szAddr;
}
/****获取网卡数目和名字****/
int SysInfo::GetInterFaceCount()
{ 
	/*CGetNetData pNet;
	DWORD pCount = pNet.GetNetworkInterfacesCount();
	return pCount;*/

	try
	{
#define DEFAULT_BUFFER_SIZE 40960L

		unsigned char *data = (unsigned char*)malloc(DEFAULT_BUFFER_SIZE);
		DWORD type;
		DWORD size = DEFAULT_BUFFER_SIZE;
		DWORD ret;

		char s_key[4096];
		sprintf_s(s_key , 4096 , "510");
		//RegQueryValueEx的固定调用格式		
		CString str(s_key);

		//如果RegQueryValueEx函数执行失败则进入循环
		while((ret = RegQueryValueEx(HKEY_PERFORMANCE_DATA, str, 0, &type, data, &size)) != ERROR_SUCCESS)
		{
			Sleep(10);
			//如果RegQueryValueEx的返回值为ERROR_MORE_DATA(申请的内存区data太小，不能容纳RegQueryValueEx返回的数据)
			if(ret == ERROR_MORE_DATA) 
			{
				Sleep(10);
				size += DEFAULT_BUFFER_SIZE;
				data = (unsigned char*) realloc(data, size);//重新分配足够大的内存

				ret = RegQueryValueEx(HKEY_PERFORMANCE_DATA, str, 0, &type, data, &size);//重新执行RegQueryValueEx函数
			} 
			//如果RegQueryValueEx返回值仍旧未成功则函数返回.....(注意内存泄露“free函数”~~~)。
			//这个if保证了这个while只能进入一次~~~避免死循环
			if(ret != ERROR_SUCCESS)
			{
				if (NULL != data)
				{
					free(data);
					data = NULL;
				}
				return 0;//0个接口
			}
		}

		//函数执行成功之后就是对返回的data内存中数据的解析了，这个建议去查看MSDN有关RegQueryValueEx函数参数数据结构的说明
		//得到数据块		
		PERF_DATA_BLOCK	 *dataBlockPtr = (PERF_DATA_BLOCK *)data;
		//得到第一个对象
		PERF_OBJECT_TYPE *objectPtr = (PERF_OBJECT_TYPE *) ((BYTE *)dataBlockPtr + dataBlockPtr->HeaderLength);

		for(int a=0 ; a<(int)dataBlockPtr->NumObjectTypes ; a++) 
		{
			char nameBuffer[255] = {0};
			if(objectPtr->ObjectNameTitleIndex == 510) 
			{
				DWORD processIdOffset = ULONG_MAX;
				PERF_COUNTER_DEFINITION *counterPtr =(PERF_COUNTER_DEFINITION *) ((BYTE *)objectPtr + objectPtr->HeaderLength);

				for(int b=0 ; b<(int)objectPtr->NumCounters ; b++) 
				{
					if(counterPtr->CounterNameTitleIndex == 520)
						processIdOffset = counterPtr->CounterOffset;

					counterPtr =(PERF_COUNTER_DEFINITION *) ((BYTE *) counterPtr + counterPtr->ByteLength);
				}

				if(processIdOffset == ULONG_MAX) {
					if(data != NULL)
					{
						free(data);
						data = NULL;
					}
					return 0;
				}

				PERF_INSTANCE_DEFINITION *instancePtr =(PERF_INSTANCE_DEFINITION *)  ((BYTE *) objectPtr + objectPtr->DefinitionLength);

				for(int b=0 ; b<objectPtr->NumInstances ; b++) 
				{
					wchar_t *namePtr = (wchar_t *) ((BYTE *)instancePtr + instancePtr->NameOffset);
					PERF_COUNTER_BLOCK *counterBlockPtr = (PERF_COUNTER_BLOCK *) ((BYTE *)instancePtr + instancePtr->ByteLength);
		
					char pName[256] = {0};
					WideCharToMultiByte(CP_ACP, 0, namePtr, -1, pName, sizeof(nameBuffer), 0, 0);

					DWORD bandwith = *((DWORD *) ((BYTE *)counterBlockPtr + processIdOffset));				
					DWORD tottraff = 0;

					Interfaces.AddTail(CString(pName)); //各网卡的名称
					Bandwidths.AddTail(bandwith);       //带宽
					TotalTraffics.AddTail(tottraff);    // 流量初始化为0

					PERF_COUNTER_BLOCK  *pCtrBlk = (PERF_COUNTER_BLOCK *) ((BYTE *)instancePtr + instancePtr->ByteLength);

					
					instancePtr = (PERF_INSTANCE_DEFINITION *) ((BYTE *)instancePtr + instancePtr->ByteLength + pCtrBlk->ByteLength);
				}
			}
			objectPtr = (PERF_OBJECT_TYPE *) ((BYTE *)objectPtr + objectPtr->TotalByteLength);
		}
		if(data != NULL)
		{
			free(data);
			data = NULL;
		}
	}
	catch(...)
	{
		return 0;
	}
	return Interfaces.GetCount();
}

void SysInfo::GetInterFaceName(CString &InterfaceName,int pNum)
{ 
	/*CGetNetData pNet;
	pNet.GetNetworkInterfaceName(&InterfaceName,pNum);*/

	POSITION pos = Interfaces.FindIndex(pNum);
	if(pos == NULL)
		return ;

	InterfaceName = Interfaces.GetAt(pos);
	pos = Bandwidths.FindIndex(pNum);
	if (pos == NULL)
		return;
	DWORD dwBandwidth = Bandwidths.GetAt(pos);

	CString str;
	str.Format(_T("%d"),dwBandwidth);

	InterfaceName = InterfaceName + str;
}

/****获取CPU名称、内核数目、主频****/
void SysInfo::GetCpuInfo(CString &chProcessorName,CString &chProcessorType,DWORD &dwNum,DWORD &dwMaxClockSpeed)
{ 
	CString strPath = _T("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0");//注册表子键路径
	CRegKey regkey;//定义注册表类对象
	LONG lResult;//LONG型变量－反应结果
	lResult = regkey.Open(HKEY_LOCAL_MACHINE,LPCTSTR(strPath),KEY_ALL_ACCESS); //打开注册表键
	if (lResult != ERROR_SUCCESS)
	{
		return;
	}
	TCHAR chCPUName[80] = {0};
	DWORD dwSize = 80; 

    //获取ProcessorNameString字段值
    if (ERROR_SUCCESS == regkey.QueryStringValue(_T("ProcessorNameString"), (LPTSTR)chCPUName, &dwSize))
	{
        chProcessorName.Format(_T("%s"), chCPUName);
	}

	//查询CPU主频
	DWORD dwValue;
	if (ERROR_SUCCESS == regkey.QueryDWORDValue(_T("~MHz"), dwValue))
	{
		dwMaxClockSpeed = dwValue;
	}
	
	regkey.Close();//关闭注册表
	
	//获取CPU核心数目
	SYSTEM_INFO si;
	memset(&si, 0, sizeof(SYSTEM_INFO));
	GetSystemInfo(&si);
	dwNum = si.dwNumberOfProcessors;
    
	switch (si.dwProcessorType)
	{
	case PROCESSOR_INTEL_386:
		{
			chProcessorType.Format(_T("Intel 386 processor"));
		}
		break;
	case PROCESSOR_INTEL_486:
		{
			chProcessorType.Format(_T("Intel 486 Processor"));
		}
		break;
	case PROCESSOR_INTEL_PENTIUM:
		{
			chProcessorType.Format(_T("Intel Pentium Processor"));
		}
		break;
	case PROCESSOR_INTEL_IA64:
		{
			chProcessorType.Format(_T("Intel IA64 Processor"));
		}
		break;
	case PROCESSOR_AMD_X8664:
		{
			chProcessorType.Format(_T("AMD X8664 Processor"));
		}
		break;
	default:
		chProcessorType.Format(_T("未知"));
		break;
	}
    
}

/****获取物理内存和虚拟内存大小****/
void  SysInfo::GetMemoryInfo(CString &dwTotalPhys,CString &dwTotalVirtual) 
{ 
	//MEMORYSTATUS Mem = {0};
    //Mem.dwLength = sizeof( MEMORYSTATUS );
	//GlobalMemoryStatus( &Mem ); 
	//float fSize = (float)Mem.dwTotalPhys/(1024*1024); 
	//float fVirtSize = (float)Mem.dwTotalVirtual/(1024*1024);
    //dwTotalPhys.Format(_T("%.2f MB"),fSize); 
    //dwTotalVirtual.Format(_T("%.2f MB"),fVirtSize);
    
    MEMORYSTATUSEX MemEx = {0};
    MemEx.dwLength = sizeof( MEMORYSTATUSEX );
    GlobalMemoryStatusEx( &MemEx );
    float fSize = (float)MemEx.ullTotalPhys/(1024*1024); 
    float fVirtSize = (float)MemEx.ullAvailVirtual/(1024*1024);
    dwTotalPhys.Format(_T("%.2f MB"),fSize); 
    dwTotalVirtual.Format(_T("%.2f MB"),fVirtSize);
    
    //dwTotalPhys.Format(_T("物理内存:%ld MB"),dwSize); 
	//dwTotalVirtual.Format(_T("虚拟内存:%ld MB"),dwVirtSize);
}

/****获取硬盘序列号****/                       //硬盘序列号1 获取模拟序列号 不精准
CString SysInfo::GetDiskSn()
{
	DWORD VolumeSerialNumber; 
	GetVolumeInformation(_T("C:\\"),NULL,12, &VolumeSerialNumber,NULL,NULL,NULL,10); 
    
    //CString SerialNumber;
    //SerialNumber.Format(_T("%xd"), VolumeSerialNumber );

#ifdef _UNICODE
    TCHAR SerialNumber[128] = _T("");
    swprintf_s(SerialNumber,_T("%xd"), VolumeSerialNumber );
#else
    TCHAR SerialNumber[128] = "";
    sprintf_s(SerialNumber,_T("%xd"), VolumeSerialNumber );
#endif
	_tcsupr_s(SerialNumber);

	return SerialNumber;
}
/****获取硬盘信息****/
void SysInfo::GetDiskInfo(DWORD &dwNum,CString csDriveInfo[])
{ 
	DWORD DiskCount = 0;

	//利用GetLogicalDrives()函数可以获取系统中逻辑驱动器的数量，函数返回的是一个32位无符号整型数据。
	DWORD DiskInfo = GetLogicalDrives();

	//通过循环操作查看每一位数据是否为1，如果为1则磁盘为真,如果为0则磁盘不存在。
	while(DiskInfo)
	{
		//通过位运算的逻辑与操作，判断是否为1
		Sleep(10);
		if(DiskInfo&1)
		{
			DiskCount++;
		}
		DiskInfo = DiskInfo >> 1;//通过位运算的右移操作保证每循环一次所检查的位置向右移动一位。*/
	}

	if (dwNum < DiskCount)
	{
		return;//实际的磁盘数目大于dwNum
	}
	dwNum = DiskCount;//将磁盘分区数量保存


	//-------------------------------------------------------------------//
	//通过GetLogicalDriveStrings()函数获取所有驱动器字符串信息长度
	int DSLength = GetLogicalDriveStrings(0,NULL);

	  TCHAR* DStr = new TCHAR[DSLength];
	  memset(DStr,0,DSLength);
      
	  //通过GetLogicalDriveStrings将字符串信息复制到堆区数组中,其中保存了所有驱动器的信息。
#ifdef _UNICODE
      GetLogicalDriveStrings(DSLength,(LPWSTR)DStr);
#else
      GetLogicalDriveStrings(DSLength,(LPSTR)DStr);
#endif

	  int DType;
	  int si=0;
	  BOOL fResult;
	  unsigned _int64 i64FreeBytesToCaller;
	  unsigned _int64 i64TotalBytes;
	  unsigned _int64 i64FreeBytes;

	  //读取各驱动器信息，由于DStr内部数据格式是A:\NULLB:\NULLC:\NULL，所以DSLength/4可以获得具体大循环范围
	  for(int i=0;i<DSLength/4;++i)
	  {
		  Sleep(10);
		  CString strdriver = DStr+i*4;
		  CString strTmp,strTotalBytes,strFreeBytes;
		  DType = GetDriveType(strdriver);//GetDriveType函数，可以获取驱动器类型，参数为驱动器的根目录
		  switch (DType)
		  {
		  case DRIVE_FIXED:
			  {
				  strTmp.Format(_T("本地磁盘"));
			  }
		  	break;
		  case DRIVE_CDROM:
			  {
				  strTmp.Format(_T("DVD驱动器"));
			  }
			  break;
		  case DRIVE_REMOVABLE:
			  {
				  strTmp.Format(_T("可移动磁盘"));
			  }
			  break;
		  case DRIVE_REMOTE:
			  {
				  strTmp.Format(_T("网络磁盘"));
			  }
			  break;
		  case DRIVE_RAMDISK:
			  {
				  strTmp.Format(_T("虚拟RAM磁盘"));
			  }
			  break;
		  case DRIVE_UNKNOWN:
			  {
				  strTmp.Format(_T("虚拟RAM未知设备"));
			  }
			  break;
		  default:
			  strTmp.Format(_T("未知设备"));
			  break;
		  }

		  //GetDiskFreeSpaceEx函数，可以获取驱动器磁盘的空间状态,函数返回的是个BOOL类型数据
		  fResult = GetDiskFreeSpaceEx (strdriver,
			  (PULARGE_INTEGER)&i64FreeBytesToCaller,
			  (PULARGE_INTEGER)&i64TotalBytes,
			  (PULARGE_INTEGER)&i64FreeBytes);
		      
		  if(fResult)
		  {
			  strTotalBytes.Format(_T(" 总容量%.2fGB"),(float)i64TotalBytes/1024/1024/1024); //磁盘
			  strFreeBytes.Format(_T(" 剩余空间%.2fGB"),(float)i64FreeBytesToCaller/1024/1024/1024); //磁盘
		  }
		  else
		  {
			  strTotalBytes.Format(_T(""));
			  strFreeBytes.Format(_T(""));
		  }
		  csDriveInfo[i] = strTmp + _T("(") + strdriver + _T("):") + strTotalBytes + strFreeBytes;
		  si+=4;
	  }

      delete [] DStr;
}

/****获取显卡信息****/
void SysInfo::GetDisplayCardInfo(DWORD &dwNum,CString chCardName[])
{ 
	HKEY keyServ;
	HKEY keyEnum;
	HKEY key;
	HKEY key2;
	LONG lResult;//LONG型变量－保存函数返回值

	//查询"SYSTEM\\CurrentControlSet\\Services"下的所有子键保存到keyServ
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services"), 0, KEY_READ, &keyServ);
	if (ERROR_SUCCESS != lResult)
		return;
    
	//查询"SYSTEM\\CurrentControlSet\\Enum"下的所有子键保存到keyEnum
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Enum"), 0, KEY_READ, &keyEnum);
	if (ERROR_SUCCESS != lResult)
		return;
    
	int i = 0,count = 0;
	DWORD size = 0,type = 0;
	for (;;++i)
	{
		Sleep(5);
		size = 512;
		TCHAR name[512] = {0};//保存keyServ下各子项的字段名称

		//逐个枚举keyServ下的各子项字段保存到name中
		lResult = RegEnumKeyEx(keyServ, i, name, &size, NULL, NULL, NULL, NULL);

		//要读取的子项不存在，即keyServ的子项全部遍历完时跳出循环
		if(lResult == ERROR_NO_MORE_ITEMS)
			break;

		//打开keyServ的子项字段为name所标识的字段的值保存到key
		lResult = RegOpenKeyEx(keyServ, name, 0, KEY_READ, &key);
		if (lResult != ERROR_SUCCESS)
		{
			RegCloseKey(keyServ);
			return;
		}
		

		size = 512;
		//查询key下的字段为Group的子键字段名保存到name
		lResult = RegQueryValueEx(key, TEXT("Group"), 0, &type, (LPBYTE)name, &size);
		if(lResult == ERROR_FILE_NOT_FOUND)
		{
			//?键不存在
			RegCloseKey(key);
			continue;
		};



		//如果查询到的name不是Video则说明该键不是显卡驱动项
		if(_tcscmp(TEXT("Video"),name)!=0)
		{
			RegCloseKey(key);
			continue;     //返回for循环
		};
		
		//如果程序继续往下执行的话说明已经查到了有关显卡的信息，所以在下面的代码执行完之后要break第一个for循环，函数返回
		lResult = RegOpenKeyEx(key, TEXT("Enum"), 0, KEY_READ, &key2);
		RegCloseKey(key);
		key = key2;
		size = sizeof(count);
		lResult = RegQueryValueEx(key, TEXT("Count"), 0, &type, (LPBYTE)&count, &size);//查询Count字段（显卡数目）

		dwNum = count;//保存显卡数目
		for(int j=0;j <count;++j)
		{
			TCHAR sz[512] = {0};
            char name[64] = {0};
            
            sprintf_s(name, 64, "%d", j);
            size = sizeof(sz);
#ifdef _UNICODE
            USES_CONVERSION;
            lResult  = RegQueryValueEx(key, A2T(name), 0, &type, (LPBYTE)sz, &size);
#else
            lResult  = RegQueryValueEx(key, name, 0, &type, (LPBYTE)sz, &size);
#endif

			lResult = RegOpenKeyEx(keyEnum, sz, 0, KEY_READ, &key2);
			if (ERROR_SUCCESS)
			{
				RegCloseKey(keyEnum);
				return;
			}
			
            ZeroMemory(sz,512);
			size = sizeof(sz);
			lResult = RegQueryValueEx(key2, TEXT("FriendlyName"), 0, &type, (LPBYTE)sz,&size);
			if(lResult == ERROR_FILE_NOT_FOUND)
			{
				ZeroMemory(sz,512);
				size = sizeof(sz);
				lResult = RegQueryValueEx(key2, TEXT("DeviceDesc"), 0, &type, (LPBYTE)sz,&size);
				//chCardName[j] = sz; //保存显卡名称
				
				CString cc = sz;
#ifdef _UNICODE
                int nPos = cc.Find(_T(';'));
                chCardName[j] = cc.Right(size/2 - nPos -2);
#else
                int nPos = cc.Find(';');
                chCardName[j] = cc.Right(size - nPos -2);
#endif

			};
			RegCloseKey(key2);
			key2 = NULL;
		};
		RegCloseKey(key);
		key = NULL;
		break;
	}
}

/****获取PID信息****/
CString SysInfo::GetPIDself()
{
    DWORD _PID = 0;
    _PID = ::GetCurrentProcessId();
	CString csPID;
	csPID.Format(_T("%d"), _PID);
	return csPID;
}
/****获取文件名****/
void GetFileNameFromPathName(CString PathName, CString& FileName, BOOL Ext = FALSE)
{
    int nPos;
    nPos = PathName.ReverseFind('\\');
    if(nPos == -1)
    {
        nPos = PathName.ReverseFind('/');
    }
    //CString FilePath = PathName.Left(nPos+1);
    /*CString*/ FileName = PathName.Right(PathName.GetLength()-1-nPos);
	if (!Ext) //TRUE=***.exe   FALSE=***
	{
		int nPos = FileName.ReverseFind('.');
		if (nPos != -1)
			FileName = FileName.Left(nPos);
	}
    return ;
}
CString SysInfo::GetSoftName()
{
	TCHAR szFull[_MAX_PATH];
	ZeroMemory( szFull, _MAX_PATH );
	::GetModuleFileName(NULL, szFull, sizeof(szFull)/sizeof(TCHAR));
	
    CString csSoftName;
    GetFileNameFromPathName( szFull, csSoftName );
    
    return csSoftName;
}

/****获取版本****/
CString SysInfo::GetSoftVersion()
{
    DWORD dwVerHnd;
    VS_FIXEDFILEINFO * pFileInfo;
    CString strVersion ;

    TCHAR szFullPath[MAX_PATH];
    ZeroMemory( szFullPath, _MAX_PATH );
    GetModuleFileName(NULL, szFullPath, sizeof(szFullPath));

    DWORD dwVerInfoSize = 0;
    dwVerInfoSize = GetFileVersionInfoSize(szFullPath, &dwVerHnd);
    
    if ( dwVerInfoSize )
    {
        // If we were able to get the information, process it:
        HANDLE  hMem;
        LPVOID  lpvMem;
        unsigned int uInfoSize = 0;
        
        hMem = GlobalAlloc(GMEM_MOVEABLE, dwVerInfoSize);
        lpvMem = GlobalLock(hMem);
        GetFileVersionInfo(szFullPath, dwVerHnd, dwVerInfoSize, lpvMem);
        
        ::VerQueryValue(lpvMem, (LPTSTR)_T("\\"), (void**)&pFileInfo, &uInfoSize);
        
        int ret = GetLastError();
        WORD m_nProdVersion[4];
        
        // Product version from the FILEVERSION of the version info resource 
        m_nProdVersion[0] = HIWORD( pFileInfo->dwProductVersionMS ); 
        m_nProdVersion[1] = LOWORD( pFileInfo->dwProductVersionMS );
        m_nProdVersion[2] = HIWORD( pFileInfo->dwProductVersionLS );
        m_nProdVersion[3] = LOWORD( pFileInfo->dwProductVersionLS ); 
        
        strVersion.Format(_T("%d.%d.%d.%d"),m_nProdVersion[0],m_nProdVersion[1],m_nProdVersion[2],m_nProdVersion[3]);
        
        GlobalUnlock(hMem);
        GlobalFree(hMem);
    }
    else
    {
        strVersion.Format(_T(""));
    }
    return strVersion;
} 
//////////////////////////////////////////////////////////////////////////
void GetHostNameFromURL(CString URLName, CString& HostUrl, CString& HostName, CString& FileName)
{
    int nPos;
    nPos = URLName.Find(_T("://"));
    if(nPos != -1)
    {
        HostUrl = URLName.Left(nPos+3);
        URLName = URLName.Right(URLName.GetLength()-3-nPos);
    }
    
    nPos = URLName.Find('/');
    HostName = URLName.Left(nPos);
    FileName = URLName.Right(URLName.GetLength()-1-nPos);
    HostUrl += HostName;
	//nPos = HostName.ReverseFind(':');
	//if (nPos != -1)
	//	HostName = HostName.Right(HostName.GetLength()-3-nPos);
    return ;
}
/****PostData****/
int SysInfo::PostData(CString strUrl, CString strAES, CString csSafeCode/*strMD5*/, CString szType, int bType = 0)
{
    //解析地址Url
    CString csUrlHost;
    CString csUrlHostName;
    CString csUrlPhpName;
    GetHostNameFromURL(strUrl, csUrlHost, csUrlHostName, csUrlPhpName);
    
	//获取文件名
	CString csFileName = GetSoftName( );
	
    //uid zid
    CString uid,zid;
	int first,last;
    first = csFileName.Find(_T("_"));
    last = csFileName.ReverseFind('_');
	if (first == -1)
	{
        uid = "";
        zid = "";
	}
	else
	{
	    if (first == last)
	    {
		    uid = csFileName.Right(csFileName.GetLength()-last-1);
		    zid = "";
	    }
	    else
	    {
		    uid = csFileName.Mid(first+1, last-first-1);
		    zid = csFileName.Right(csFileName.GetLength()-last-1);
	    }
	}

    //当前时间
    SYSTEMTIME tm;
    GetSystemTime( &tm );
    CString csTime;
    csTime.Format(_T("%0.2d-%0.2d-%0.2d %0.2d:%0.2d:%0.2d"),tm.wYear,tm.wMonth,tm.wDay,tm.wHour,tm.wMinute,tm.wSecond);
    
    //获取版本
    CString csSoftVersion = GetSoftVersion( );

    //获取PID
    CString csPID = GetPIDself();

    //获取UserName
    CString csUserName = GetUserInfo();
    
    //获取HostName
    CString csHostName = GetHostInfo();
    
    //获取DiskSN
    CString csDiskSn = GetDiskSn();
    
    //获取MAC
    CString csMac = GetMacAddress();
    
    //if (bType == 2)
    //{
        //获取CPU
        CString csProcessorName, csProcessorType;
        DWORD dwNum, dwMaxClockSpeed;
        GetCpuInfo( csProcessorName, csProcessorType, dwNum, dwMaxClockSpeed );
        
        //获取内存
        CString csMemoryPhys, csMemoryVirtual;
        GetMemoryInfo( csMemoryPhys, csMemoryVirtual );
        
        //获取OS Version
        TCHAR szOS[256];
        ZeroMemory(szOS, 256);
        GetOSDisplayString( szOS );
        CString csOSVersion;
        csOSVersion.Format(_T("%s"),szOS);
    //}
    
    CString	szFormData = "";//   = "userid=2[11]&mac=ceshi&mid=1&pid=1&did=1&key=19c5b8fa28cc523f572ffd4e442a1159";
    if (bType == 0) //界面旧版 0-AES加密
    {
        //防作弊算法
        CString csKey;
        csKey.Format(_T("%s%s%s%s\0"),csMac, csDiskSn, csSafeCode, csTime);
        char *MD5buf = NULL;
#ifdef _UNICODE
        USES_CONVERSION;
        MD5buf = MD5String(T2A(csKey.GetBuffer()));
#else
        MD5buf = MD5String(csKey.GetBuffer());
#endif
        
        //AES加密
        Cipher aes;
        char* cc;
#ifdef _UNICODE
        //USES_CONVERSION;
        cc = aes.aes_encode(T2A(szType.GetBuffer()),T2A(strAES.GetBuffer()));
        szType.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csFileName.GetBuffer()),T2A(strAES.GetBuffer()));
        csFileName.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csSoftVersion.GetBuffer()),T2A(strAES.GetBuffer()));
        csSoftVersion.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csUserName.GetBuffer()),T2A(strAES.GetBuffer()));
        csUserName.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csHostName.GetBuffer()),T2A(strAES.GetBuffer()));
        csHostName.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csOSVersion.GetBuffer()),T2A(strAES.GetBuffer()));
        csOSVersion.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csProcessorName.GetBuffer()),T2A(strAES.GetBuffer()));
        csProcessorName.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csMemoryPhys.GetBuffer()),T2A(strAES.GetBuffer()));
        csMemoryPhys.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csMac.GetBuffer()),T2A(strAES.GetBuffer()));
        csMac.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csDiskSn.GetBuffer()),T2A(strAES.GetBuffer()));
        csDiskSn.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csPID.GetBuffer()),T2A(strAES.GetBuffer()));
        csPID.Format(_T("%s"), A2T(cc));
        cc = aes.aes_encode(T2A(csTime.GetBuffer()),T2A(strAES.GetBuffer()));
        csTime.Format(_T("%s"), A2T(cc));
#else
        cc = aes.aes_encode(szType.GetBuffer(),strAES.GetBuffer());
        szType.Format(_T("%s"), cc);
        cc = aes.aes_encode(csFileName.GetBuffer(),strAES.GetBuffer());
        csFileName.Format(_T("%s"), cc);
        cc = aes.aes_encode(csSoftVersion.GetBuffer(),strAES.GetBuffer());
        csSoftVersion.Format(_T("%s"), cc);
        cc = aes.aes_encode(csUserName.GetBuffer(),strAES.GetBuffer());
        csUserName.Format(_T("%s"), cc);
        cc = aes.aes_encode(csHostName.GetBuffer(),strAES.GetBuffer());
        csHostName.Format(_T("%s"), cc);
        cc = aes.aes_encode(csOSVersion.GetBuffer(),strAES.GetBuffer());
        csOSVersion.Format(_T("%s"), cc);
        cc = aes.aes_encode(csProcessorName.GetBuffer(),strAES.GetBuffer());
        csProcessorName.Format(_T("%s"), cc);
        cc = aes.aes_encode(csMemoryPhys.GetBuffer(),strAES.GetBuffer());
        csMemoryPhys.Format(_T("%s"), cc);
        cc = aes.aes_encode(csMac.GetBuffer(),strAES.GetBuffer());
        csMac.Format(_T("%s"), cc);
        cc = aes.aes_encode(csDiskSn.GetBuffer(),strAES.GetBuffer());
        csDiskSn.Format(_T("%s"), cc);
        cc = aes.aes_encode(csPID.GetBuffer(),strAES.GetBuffer());
        csPID.Format(_T("%s"), cc);
        cc = aes.aes_encode(csTime.GetBuffer(),strAES.GetBuffer());
        csTime.Format(_T("%s"), cc);
#endif
        
        //Post信息
#ifdef _UNICODE
        //USES_CONVERSION;
        szFormData.Format(_T("type=%s&soft=%s&ver=%s&name=%s&host=%s&os=%s&cpu=%s&mem=%s&mac=%s&did=%s&pid=%s&tm=%s&mid=%s\0"),szType,csFileName,csSoftVersion,csUserName,csHostName,csOSVersion,csProcessorName,csMemoryPhys,csMac,csDiskSn,csPID,csTime,A2T(MD5buf));
#else
        szFormData.Format(_T("type=%s&soft=%s&ver=%s&name=%s&host=%s&os=%s&cpu=%s&mem=%s&mac=%s&did=%s&pid=%s&tm=%s&mid=%s\0"),szType,csFileName,csSoftVersion,csUserName,csHostName,csOSVersion,csProcessorName,csMemoryPhys,csMac,csDiskSn,csPID,csTime,MD5buf);
#endif
    }
    else if (bType == 1) //界面旧版1-RTYUDHHS
    {
        //防作弊算法
        CString csKey;
        csKey.Format(_T("%s%s%s%s\0"),csMac, csDiskSn, csSafeCode, csTime);
        char *MD5buf = NULL;
#ifdef _UNICODE
        USES_CONVERSION;
        MD5buf = MD5String(T2A(csKey.GetBuffer()));
#else
        MD5buf = MD5String(csKey.GetBuffer());
#endif
        
        //Post信息
#ifdef _UNICODE
        //USES_CONVERSION;
        szFormData.Format(_T("type=%s&soft=%s&ver=%s&name=%s&host=%s&os=%s&cpu=%s&mem=%s&mac=%s&did=%s&pid=%s&tm=%s&mid=%s\0"),szType,csFileName,csSoftVersion,csUserName,csHostName,csOSVersion,csProcessorName,csMemoryPhys,csMac,csDiskSn,csPID,csTime,A2T(MD5buf));
#else
        szFormData.Format(_T("type=%s&soft=%s&ver=%s&name=%s&host=%s&os=%s&cpu=%s&mem=%s&mac=%s&did=%s&pid=%s&tm=%s&mid=%s\0"),szType,csFileName,csSoftVersion,csUserName,csHostName,csOSVersion,csProcessorName,csMemoryPhys,csMac,csDiskSn,csPID,csTime,MD5buf);
#endif
    }
    else if (bType == 2) //界面改版
    {
        //防作弊算法   csSafeCode = 5ea90d50ecae7d9244f687f956bc9dbe  9d3e9da21d447d2edb6a98518ea58b47
        CString csKey;
        csKey.Format(_T("%s+%s"),csMac ,csSafeCode);
        char *MD5buf = NULL;
#ifdef _UNICODE
        USES_CONVERSION;
        MD5buf = MD5String(T2A(csKey.GetBuffer()));
#else
        MD5buf = MD5String(csKey.GetBuffer());
#endif
        
        //Post信息
#ifdef _UNICODE
        //USES_CONVERSION;
        szFormData.Format(_T("userid=%s[%s]&u=%s&ver=%s&name=%s&host=%s&mac=%s&did=%s&pid=%s&mid=%s&key=%s\0"),uid,zid,csFileName,csSoftVersion,csUserName,csHostName,csMac,csDiskSn,csPID,strAES,A2T(MD5buf));
#else
        szFormData.Format(_T("userid=%s[%s]&u=%s&ver=%s&name=%s&host=%s&mac=%s&did=%s&pid=%s&mid=%s&key=%s\0"),uid,zid,csFileName,csSoftVersion,csUserName,csHostName,csMac,csDiskSn,csPID,strAES,(MD5buf));
#endif
    }
    
    //Post连接信息
	CString csReferer;
	csReferer.Format(_T("Referer: %s"), csUrlHost);
	CString strHeaders  = _T("Content-Type: application/x-www-form-urlencoded");
    
	HINTERNET	hSession;   
	HINTERNET   hConnect;   
	HINTERNET   hRequest;   
	BOOL		bReturn	 = FALSE;
	//使用Wininet相关API建立链接
	hSession = InternetOpen( _T("AutoVoteVisPostMethod"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0 );
	if ( hSession == NULL )
	{
		InternetCloseHandle( hSession );
		return 0;
	}
	hConnect = InternetConnect( hSession, csUrlHostName.GetBuffer()/*_T("www.tongji2.com")*/, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP,0,1 );
	if ( hConnect == NULL )
	{
		InternetCloseHandle( hConnect );
		InternetCloseHandle( hSession );
		return 0;
	}
	hRequest = HttpOpenRequest( hConnect, _T("POST"), csUrlPhpName.GetBuffer(), _T("HTTP/1.1"), strHeaders.GetBuffer(), NULL, INTERNET_FLAG_RELOAD, 1 );
	if ( !hRequest )
	{
		InternetCloseHandle( hConnect );
		InternetCloseHandle( hSession );
		return 0;
	}
	
	//////////////////////////////////////////////////////////////////////////提交数据
    char   szSendBuf[1024] = {0};     // 发送数据缓冲区 
#ifdef _UNICODE
    USES_CONVERSION;
    memcpy(szSendBuf, T2A(szFormData.GetBuffer()), szFormData.GetLength());
#else
    memcpy(szSendBuf, szFormData.GetBuffer(), szFormData.GetLength());
#endif
    LPVOID pBuf = (LPVOID)szSendBuf;
	bReturn = HttpSendRequest( hRequest, strHeaders, strHeaders.GetLength(), (LPVOID)pBuf, szFormData.GetLength() );  //不支持UNICODE
	if( !bReturn )
	{
	    //::MessageBox(NULL, _T("发送Http请求失败！"), _T("提示"), MB_OK);
		InternetCloseHandle( hRequest );
		InternetCloseHandle( hConnect );
		InternetCloseHandle( hSession );
		return 0;
	}
	//////////////////////////////////////////////////////////////////////////接受数据
    char   szRecvBuf[1024] = {0};     // 接受数据缓冲区   
    DWORD  dwNumberOfBytesRead = 0;   // 服务器返回大小   
    DWORD  dwRecvTotalSize = 0;       // 接受数据总大小   
    DWORD  dwRecvBuffSize = 0;        // 接受数据buf的大小   
    do  
    {      
        // 开始读取数据
        bReturn = InternetReadFile(hRequest, szRecvBuf, 1024, &dwNumberOfBytesRead);   //使用你提供的缓冲读指定的字节
        if(!bReturn)
        {   
            //MessageBox("InternetReadFile Error !","提示",MB_ICONERROR | MB_OK);   
            break;   
        }
        // 统计接受数据的大小   
        szRecvBuf[dwNumberOfBytesRead] = '\0';   
        dwRecvTotalSize += dwNumberOfBytesRead;   
        dwRecvBuffSize  += strlen(szRecvBuf);
    } while(dwNumberOfBytesRead != 0);
    //////////////////////////////////////////////////////////////////////////
    return 0;
}
//////////////////////////////////////////////////////////////////////////