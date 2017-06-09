###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-081.nasl 32358 2013-10-09 09:00:42Z oct$
#
# MS Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2870008)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_id(903500);
  script_version("$Revision: 6074 $");
  script_cve_id("CVE-2013-3128", "CVE-2013-3200", "CVE-2013-3879", "CVE-2013-3880",
                "CVE-2013-3881", "CVE-2013-3888", "CVE-2013-3894");
  script_bugtraq_id(62819, 62823, 62828, 62833, 62830, 62831, 62821);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-05 11:03:14 +0200 (Fri, 05 May 2017) $");
  script_tag(name:"creation_date", value:"2013-10-09 09:16:37 +0530 (Wed, 09 Oct 2013)");
  script_name("MS Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2870008)");

  tag_summary =
"This host is missing an critical security update according to
Microsoft Bulletin MS13-081";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws are due to ,
- An error when parsing OpenType fonts (OTF) can be exploited to corrupt
  memory.
- An error when handling the USB descriptor of inserted USB devices can be
  exploited to corrupt memory.
- A use-after-free error within the kernel-mode driver (win32k.sys) can be
  exploited to gain escalated privileges.
- An error when handling objects in memory related to App Containers can
  be exploited to disclose information from a different App Container.
- An error related to NULL page handling within the kernel-mode driver
  (win32k.sys) can be exploited to gain escalated privileges.
- A double fetch error within the DirectX graphics kernel subsystem
  (dxgkrnl.sys) can be exploited to gain escalated privileges.
- An error when parsing the CMAP table while rendering TrueType
   fonts (TTF) can be exploited to corrupt memory.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
code with kernel-mode privileges and take complete control of the affected
system.

Impact Level: System";

  tag_affected =
"Microsoft Windows 8
Microsoft Windows Server 2012
Microsoft Windows XP x32 Edition Service Pack 3 and prior
Microsoft Windows XP x64 Edition Service Pack 2 and prior
Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-081";


   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "vuldetect" , value : tag_vuldetect);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "impact" , value : tag_impact);
   script_tag(name:"qod_type", value:"registry");
   script_tag(name:"solution_type", value:"VendorFix");
   script_xref(name : "URL" , value : "http://secunia.com/advisories/55052/");
   script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2862330");
   script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-081");
   script_category(ACT_GATHER_INFO);
   script_copyright("Copyright (C) 2013 SecPod");
   script_family("Windows : Microsoft Bulletins");
   script_dependencies("smb_reg_service_pack.nasl");
   script_mandatory_keys("SMB/WindowsVersion");
   exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
usbdSysver="";
atmfdVer="";
hidparseVer="";
win32SysVer="";
dwVer = "";
cddVer = "";
wdVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
  win7x64:2, win2008:3, win2008r2:2, win8:1, win2012:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

atmfdVer = fetch_file_version(sysPath, file_name:"system32\atmfd.dll");
usbdSysVer = fetch_file_version(sysPath, file_name:"system32\drivers\usbd.sys");
hidparseVer = fetch_file_version(sysPath, file_name:"system32\drivers\hidparse.sys");
win32SysVer = fetch_file_version(sysPath, file_name:"system32\win32k.sys");
fontsubVer = fetch_file_version(sysPath, file_name:"system32\Fontsub.dll");
dwVer = fetch_file_version(sysPath, file_name:"system32\Dwrite.dll");
cddVer  =  fetch_file_version(sysPath, file_name:"system32\cdd.dll");
wdVer = fetch_file_version(sysPath, file_name:"system32\Wdfres.dll");

if(usbdSysVer || atmfdVer ||  hidparseVer ||
   win32SysVer ||  dwVer || cddVer || wdVer)
{

  ## Windows XP
  if(hotfix_check_sp(xp:4) > 0)
  {
    ## Grep for the file version
    if(version_is_less(version:atmfdVer, test_version:"5.1.2.236") ||
       version_is_less(version:usbdSysVer, test_version:"5.1.2600.6437") ||
       version_is_less(version:hidparseVer, test_version:"5.1.2600.6418") ||
       version_is_less(version:win32SysVer, test_version:"5.1.2600.6442")){
      security_message(0);
   }
    exit(0);
  }

  ## Windows XP Professional x64 edition and Windows Server 2003
  if(hotfix_check_sp(xpx64:3,win2003x64:3,win2003:3) > 0)
  {
    ## Grep for file version
    ## Grep for the file version
    if(version_is_less(version:atmfdVer, test_version:"5.1.2.236") ||
       version_is_less(version:usbdSysVer, test_version:"5.2.3790.5203") ||
       version_is_less(version:hidparseVer, test_version:"5.2.3790.5189") ||
       version_is_less(version:win32SysVer, test_version:"5.2.3790.5216")){
     security_message(0);
    }
    exit(0);
  }

  ## Windows Vista and Windows Server 2008
  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    ## Check for Win32k.sys version
    if(version_is_less(version:fontsubVer, test_version:"6.0.6002.18272") ||
       version_in_range(version:fontsubVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23131")||
       version_is_less(version:usbdSysVer, test_version:"6.0.6002.18875") ||
       version_in_range(version:usbdSysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23146")||
       version_is_less(version:hidparseVer, test_version:"6.0.6002.18878") ||
       version_in_range(version:hidparseVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23149")||
       version_is_less(version:win32SysVer, test_version:"6.0.6002.18927") ||
       version_in_range(version:win32SysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23203") ||
       version_is_less(version:dwVer, test_version:"7.0.6002.18923") ||
       version_in_range(version:dwVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23199") ||
       version_is_less(version:cddVer, test_version:"7.0.6002.18392") ||
       version_in_range(version:cddVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23180") ||
       version_is_less(version:wdVer, test_version:"6.2.9200.16384")){
       ## version_in_range(version:wdVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16384") ||
     security_message(0);
    }
    exit(0);
  }

  ## Windows 7 and Windows Server 2008 R2
  if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    ## Check for Win32k.sys version
    if(version_is_less(version:fontsubVer, test_version:"6.1.7601.18177") ||
       version_in_range(version:fontsubVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22349")||
       version_is_less(version:usbdSysVer, test_version:"6.1.7601.18251") ||
       version_in_range(version:usbdSysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22440")||
       version_is_less(version:hidparseVer, test_version:"6.1.7601.18199") ||
       version_in_range(version:hidparseVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22373")||
       version_is_less(version:win32SysVer, test_version:"6.1.7601.18246") ||
       version_in_range(version:win32SysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22434") ||
       version_is_less(version:dwVer, test_version:"6.1.7601.18245") ||
       version_in_range(version:dwVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22433") ||
       version_is_less(version: cddVer, test_version:"6.1.7601.17514") ||
       version_in_range(version: cddVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.17513") ||
       version_is_less(version:wdVer, test_version:"6.2.9200.16384")){
       ## version_in_range(version:wdVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16384") ||
      security_message(0);
    }
    exit(0);
  }

  ## Windows 8 and Windows Server 2012
  if(hotfix_check_sp(win8:1, win2012:1) > 0)
  {
    ## Check for Win32k.sys version
    if(version_is_less(version:fontsubVer, test_version:"6.2.9200.16453") ||
       #version_in_range(version:fontsubVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.16383") ||
       version_is_less(version:usbdSysVer, test_version:"6.2.9200.16654") ||
       version_in_range(version:usbdSysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20760")||
       version_is_less(version:hidparseVer, test_version:"6.2.9200.16654") ||
       version_in_range(version:hidparseVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20762")||
       version_is_less(version:win32SysVer, test_version:"6.2.9200.16699") ||
       version_in_range(version:win32SysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20806") ||
       version_is_less(version:wdVer, test_version:"6.2.9200.16384")){
       ## version_in_range(version:wdVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16384")
      security_message(0);
    }
   exit(0);
  }
}
