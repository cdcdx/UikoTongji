//************************************************************
//  UikoTongji - NSIS Cipher Library
//
//  File: Tongji.cpp
//  Version: 2.0.0.2001
//  CreateDate: 2013-01-04
//  LastDate: 2014-09-03
//
//  Author: Garfield
//
//  Copyright (c) 2012-2015, Uiko Develop Team.
//  All Rights Reserved.
//************************************************************
#include "stdafx.h"
#include "SysInfo.h"

#include <atlstr.h>
#include <string>

#include "exdll.h"

//#pragma warning(disable:4099)

using namespace std;

#define MAX_STRLEN       1024

TCHAR strarg[1024*sizeof(TCHAR)];

unsigned char staticCnvBuffer[1024*2];

#ifdef UNICODE
#define wcslen lstrlenW
#define wcscpy lstrcpyW
#define wcsncpy lstrcpynW
#define wcscat lstrcatW
#define wcscmp lstrcmpW
#define wcscmpi lstrcmpiW
//char * _T2A(unsigned short *wideStr)
//{
//	WideCharToMultiByte(CP_ACP, 0, wideStr, -1, (char *)staticCnvBuffer, sizeof(staticCnvBuffer), NULL, NULL);
//	return (char *)staticCnvBuffer;
//}
//#define _A2T(x) _A2U(x)
#else
#define strlen lstrlenA
#define strcpy lstrcpyA
#define strncpy lstrcpynA
#define strcat lstrcatA
#define strcmp lstrcmpA
#define strcmpi lstrcmpiA
#define _T2A(x) (x)
#define _A2T(x) (x)
#endif
unsigned short * _A2U(char *ansiStr)
{
	MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, (LPWSTR)staticCnvBuffer, sizeof(staticCnvBuffer)/2);
	return (unsigned short *)staticCnvBuffer;
}

//UserName
extern "C" void __declspec(dllexport) GetUser(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	EXDLL_INIT();
	{
        SysInfo pSysInfo;
        CString csUserName = pSysInfo.GetUserInfo( );
        pushstring(csUserName.GetBuffer());
	}
    
    //char szBuffer[MAX_PATH];  
    //DWORD dwNameLen = 0;  
    //ZeroMemory(szBuffer,MAX_PATH);

    //if ( !GetUserName(szBuffer, &dwNameLen) )  
    //    pushint( GetLastError() ); 
    //else
    //    pushstring( szBuffer );
}
//HostName
extern "C" void __declspec(dllexport) GetHostName(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	EXDLL_INIT();
	{
        SysInfo pSysInfo;
        CString csHostName = pSysInfo.GetHostInfo( );
        pushstring(csHostName.GetBuffer());
        
        //char szBuffer[MAX_PATH];  
        //DWORD dwNameLen = 0;  
        //ZeroMemory(szBuffer,MAX_PATH);
        //
        //if ( !GetComputerNameEx((COMPUTER_NAME_FORMAT)1, szBuffer, &dwNameLen) )  
        ////if ( !GetComputerName(szBuffer, &dwNameLen) )  
        //    pushint( GetLastError() );  
        //else
        //    pushstring( szBuffer );
    }
    
}
//OS Version
extern "C" void __declspec(dllexport) GetOSVersion(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	char string_osver [MAX_STRLEN] = "";

	EXDLL_INIT();
	{
		
        TCHAR szOS[256];
        ZeroMemory(szOS, 256);
        SysInfo pSysInfo;
        pSysInfo.GetOSDisplayString( szOS );
        pushstring(szOS);
        
        //CString strOSVersion,strServiceVersion;
        //SysInfo pSysInfo;
        //pSysInfo.GetOSVersion(strOSVersion, strServiceVersion);
        //strcpy_s(string_osver, strOSVersion);
		//pushstring(string_osver);
	}
}

//MAC
extern "C" void __declspec(dllexport) GetMACAddress(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	//char string_mac [MAX_STRLEN] = "";

	EXDLL_INIT();
	{
		//CString csMacName;
		//DWORD dwNum = 0;
		//SysInfo pSysInfo;
		//dwNum = pSysInfo.GetInterFaceCount();
        //pSysInfo.GetInterFaceName(csMacName,0);

        SysInfo pSysInfo;
        CString csMacName = pSysInfo.GetMacAddress();
		//strcpy_s(string_mac, csMacName);

		pushstring(csMacName.GetBuffer());
	}
}

//CPU型号
extern "C" void __declspec(dllexport) GetCPUModel(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	char string_cpu [MAX_STRLEN] = "";

	EXDLL_INIT();
	{
		CString csProcessorName, csProcessorType;
		DWORD dwNum, dwMaxClockSpeed;

		SysInfo pSysInfo;
		pSysInfo.GetCpuInfo( csProcessorName, csProcessorType, dwNum, dwMaxClockSpeed );

		pushstring(csProcessorName.GetBuffer());
	}
}

//内存大小
extern "C" void __declspec(dllexport) GetMemorySize(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	//char string_memPhys [MAX_STRLEN] = "";
	//char string_memVirtual [MAX_STRLEN] = "";

	EXDLL_INIT();
	{
		CString csMemoryPhys, csMemoryVirtual;

		SysInfo pSysInfo;
		pSysInfo.GetMemoryInfo( csMemoryPhys, csMemoryVirtual );

        //strcpy_s(string_memPhys, csMemoryPhys);
        pushstring(csMemoryPhys.GetBuffer());
        
        //strcpy_s(string_memVirtual, csMemoryVirtual);
        //pushstring(string_memVirtual);
	}
}
//硬盘大小
extern "C" void __declspec(dllexport) GetDiskInfo(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	//char string_Disk [MAX_STRLEN] = "";

	EXDLL_INIT();
	{
	    DWORD DiskCount;
		CString csDiskInfo[MAX_PATH];
		SysInfo pSysInfo;
		pSysInfo.GetDiskInfo( DiskCount, csDiskInfo );
        //strcpy_s(string_Disk, csDiskInfo[0]);

        pushstring(csDiskInfo[0].GetBuffer());
	}
}
//硬盘序列号
extern "C" void __declspec(dllexport) GetDiskSn(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	//char string_Disk [MAX_STRLEN] = "";

	EXDLL_INIT();
	{
        SysInfo pSysInfo;
        CString csDiskSN = pSysInfo.GetDiskSn();
        //strcpy_s(string_Disk, csDiskSN);

        pushstring(csDiskSN.GetBuffer());
	}
}
//显卡型号
extern "C" void __declspec(dllexport) GetCardInfo(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	//char string_Card [MAX_STRLEN] = "";

	EXDLL_INIT();
	{
	    DWORD CardCount;
		CString csCardnfo[MAX_PATH];
        
		SysInfo pSysInfo;
		pSysInfo.GetDisplayCardInfo( CardCount, csCardnfo );

        //strcpy_s(string_Card, csCardnfo[0]);
        pushstring(csCardnfo[0].GetBuffer());
	}
}
//PID
extern "C" void __declspec(dllexport) GetPIDSelf(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	EXDLL_INIT();
	{
        SysInfo pSysInfo;
        CString csPID = pSysInfo.GetPIDself( );
        pushstring(csPID.GetBuffer());
	}
}
//POSTDATA
extern "C" void __declspec(dllexport) PostData(HWND hwndParent, int string_size, TCHAR *variables, stack_t **stacktop)
{
	EXDLL_INIT();
	{
        
        TCHAR strUrl[MAX_PATH];
        TCHAR strAES[MAX_PATH];
        TCHAR strMD5[MAX_PATH];
        ZeroMemory( strUrl, MAX_PATH );
        ZeroMemory( strAES, MAX_PATH );
        ZeroMemory( strMD5, MAX_PATH );
        popstring( strUrl );
        popstring( strAES );
        popstring( strMD5 );
        int bType = popint( );
        
        SysInfo pSysInfo;
        pSysInfo.PostData(strUrl, strAES, strMD5, _T("inst"), bType);
	}
}