###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-006.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Vulnerability in Windows Shell Graphics Processing Could Allow Remote Code Execution (2483185)
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code by
  tricking a user into opening or previewing a malformed Office file or browsing
  to a network share, UNC, or WebDAV location containing a specially crafted
  thumbnail image.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is due to a signedness error in the 'CreateSizedDIBSECTION()'
  function within the Windows Shell graphics processor when parsing thumbnail bitmaps.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS11-006.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-006.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902334");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_cve_id("CVE-2010-3970", "CVE-2011-0347");
  script_bugtraq_id(45662);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Vulnerability in Windows Shell Graphics Processing Could Allow Remote Code Execution (2483185)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42779");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1024932");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0018");

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
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

## MS11-006 Hotfix
if((hotfix_missing(name:"2483185") == 0)){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = fetch_file_version(sysPath, file_name:"Shell32.dll");
  if(dllVer)
  {
    # Windows XP
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 3" >< SP)
      {
        # Grep for Shell32.dll version < 6.0.2900.6072
    	if(version_is_less(version:dllVer, test_version:"6.0.2900.6072")){
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
        # Grep for Shell32.dll version < 6.0.3790.4822
        if(version_is_less(version:dllVer, test_version:"6.0.3790.4822")){
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
  dllVer = fetch_file_version(sysPath, file_name:"System32\Shell32.dll");
  if(dllVer)
  {
    # Windows Vista and windows 2008 server
    if(hotfix_check_sp(winVista:3, win2008:3) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");

      if(!SP) {
       SP = get_kb_item("SMB/Win2008/ServicePack");
      }

      if("Service Pack 1" >< SP)
      {
        # Grep for Shell32.dll version < 6.0.6001.18588
        if(version_in_range(version:dllVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18587")||
           version_in_range(version:dllVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22838")){
           security_message(0);
        }
        exit(0);
      }

      if("Service Pack 2" >< SP)
      {
        # Grep for Shell32.dll version < 6.0.6002.18393
        if(version_in_range(version:dllVer, test_version:"6.0.6002.18000" ,test_version2:"6.0.6002.18392")||
           version_in_range(version:dllVer, test_version:"6.0.6002.22000" ,test_version2:"6.0.6002.22573")){
             security_message(0);
        }
        exit(0);
      }
    }
  }
}
