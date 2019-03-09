#ifndef _H_GETSYSINFO
#define _H_GETSYSINFO

#pragma once


#include "stdafx.h"
#include <afxtempl.h>

class SysInfo
{
public:
	SysInfo(void);
	~SysInfo(void);

public:
	/****获取操作系统版本，Service pack版本、系统类型****/
	BOOL GetOSDisplayString( LPTSTR pszOS);
	CString GetNtVersionNumbers(DWORD&dwMajorVer, DWORD& dwMinorVer,DWORD& dwBuildNumber);
    void GetOSVersion(CString &strOSVersion,CString &strServiceVersion);

    /****获取操作系统位数****/
    BOOL IsWow64();//判断是否为64位操作系统

    /****获取用户名****/
    CString GetUserInfo();
    //void GetUserInfo(CString &csUserName);
    /****获取计算机名****/
    CString GetHostInfo();
    //void GetHostInfo(CString &csHostName);
    
    /****获取网卡地址****/
	CString GetMacAddress();
	/****获取网卡数目和名字****/
	int  GetInterFaceCount();
	void GetInterFaceName(CString &InterfaceName,int pNum);
	
    /****获取CPU名称、内核数目、主频****/
    void GetCpuInfo(CString &chProcessorName, CString &chProcessorType, DWORD &dwNum, DWORD &dwMaxClockSpeed);

	/****获取物理内存和虚拟内存大小****/
    void GetMemoryInfo(CString &dwTotalPhys, CString &dwTotalVirtual);
    
    /****获取硬盘序列号****/
    CString GetDiskSn();
	/****获取硬盘信息****/
	void GetDiskInfo(DWORD &dwNum,CString csDriveInfo[]);

	/****获取显卡信息****/
	void GetDisplayCardInfo(DWORD &dwNum,CString chCardName[]);
	
	/****获取PID信息****/
	CString GetPIDself();
    //void GetPIDself(CString &csPID);

    /****获取SoftName****/
    CString GetSoftName();
    /****获取版本****/
    CString GetSoftVersion();
    /****Post数据****/
    int PostData(CString strUrl, CString strAES, CString csSafeCode/*strMD5*/, CString szType, int bType);
private:
	CStringList Interfaces;		              //保存所有网卡的名字
	CList < DWORD, DWORD &>		Bandwidths;	      //各网卡的带宽
	CList < DWORD, DWORD &>		TotalTraffics;    //各网卡的总流量
};

#endif
