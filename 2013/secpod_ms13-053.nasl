###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-053.nasl 30598 2013-07-10 14:18:13Z Jul$
#
# MS Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2850851)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to cause a buffer
  overflow and execute arbitrary code with kernel privileges.
  Impact Level: System";

tag_affected = "Microsoft Windows 8
  Microsoft Windows Server 2012
  Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "Multiple flaws are due to,
  - Unspecified errors within the Windows kernel-mode driver (win32k.sys) when
    processing certain objects and can be exploited to cause a crash or execute
    arbitrary code with the kernel privilege.
  - An error exists within the GDI+ subsystem.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  https://technet.microsoft.com/en-us/security/bulletin/ms13-053";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS13-053.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902978");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1300", "CVE-2013-1340", "CVE-2013-1345", "CVE-2013-3129",
                "CVE-2013-3167", "CVE-2013-3172", "CVE-2013-3173", "CVE-2013-3660");
  script_bugtraq_id(60946, 60947, 60948, 60978, 60949, 60951, 60950, 60051);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-07-10 08:46:58 +0530 (Wed, 10 Jul 2013)");
  script_name("MS Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2850851)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53435/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2850851");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028746");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-053");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
Win32sysVer = "";

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

## Get Version from Win32k.sys file
Win32sysVer = fetch_file_version(sysPath, file_name:"system32\Win32k.sys");
if(!Win32sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Grep for Win32k.sys < 5.1.2600.6404
  if(version_is_less(version:Win32sysVer, test_version:"5.1.2600.6404")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Grep for Win32k.sys version < 5.2.3790.5174
  if(version_is_less(version:Win32sysVer, test_version:"5.2.3790.5174")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:Win32sysVer, test_version:"6.0.6002.18861") ||
     version_in_range(version:Win32sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23131")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows Server 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:Win32sysVer, test_version:"6.1.7601.18176") ||
     version_in_range(version:Win32sysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22347")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and Windows Server 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
 ## Check for Win32k.sys version
  if(version_is_less(version:Win32sysVer, test_version:"6.2.9200.16627") ||
     version_in_range(version:Win32sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20731")){
    security_message(0);
  }
  exit(0);
}
