###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-011.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows Kernel Elevation of Privilege Vulnerability (2393802)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers or malicious users to
  execute arbitrary code with kernel privileges.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 7
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.";
tag_insight = "The flaws are due to
  - an integer truncation error in the Windows kernel that does not properly
    validate user-supplied data before allocating memory.
  - a buffer overflow error in the 'win32k.sys' driver when interacting with
    the Windows kernel.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms11-011.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-011.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902337");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_cve_id("CVE-2010-4398", "CVE-2011-0045");
  script_bugtraq_id(45045, 46136);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Kernel Elevation of Privilege Vulnerability (2393802)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42356");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0324");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/cve/CVE-2011-0045");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms11-011.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
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

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-011 Hotfix
if((hotfix_missing(name:"2393802") == 0)){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = fetch_file_version(sysPath, file_name:"Ntoskrnl.exe");
  if(dllVer)
  {
    # Windows XP
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 3" >< SP)
      {
        # Grep for Ntoskrnl.exe version < 5.1.2600.6055
    	if(version_is_less(version:dllVer, test_version:"5.1.2600.6055")){
          security_message(0);
        }
        exit(0);
      }
      security_message(0);
    }

    # Windows 2003
    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Grep for Ntoskrnl.exe version < 5.2.3790.4789
        if(version_is_less(version:dllVer, test_version:"5.2.3790.4789")){
           security_message(0);
        }
        exit(0);
      }
       security_message(0);
    }
  }
}

## Get System32 path for Windows 2008 server and vista
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");

if(sysPath)
{
  dllVer = fetch_file_version(sysPath, file_name:"System32\Ntoskrnl.exe");
  if(dllVer)
  {
    # Windows Vista and 2008 server
    if(hotfix_check_sp(winVista:3, win2008:3) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");

      if(!SP) {
        SP = get_kb_item("SMB/Win2008/ServicePack");
      }

      if("Service Pack 1" >< SP)
      {
        # Grep for Ntoskrnl.exe version
        if(version_in_range(version:dllVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18537")||
           version_in_range(version:dllVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22776")){
           security_message(0);
        }
        exit(0);
      }

      if("Service Pack 2" >< SP)
      {
        # Grep for Ntoskrnl.exe version
        if(version_in_range(version:dllVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18326")||
           version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22504")){
           security_message(0);
        }
        exit(0);
      }
      security_message(0);
    }

    # Windows 7
    else if(hotfix_check_sp(win7:2) > 0)
    {
      ## Check for Ntoskrnl.exe version
      if(version_in_range(version:dllVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16694")||
         version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20825")){
        security_message(0);
      }
    }
  }
}
