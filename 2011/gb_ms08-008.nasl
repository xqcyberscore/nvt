###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-008.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Vulnerability in OLE Automation Could Allow Remote Code Execution (947890)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2000 Service Pack 4 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista
  Microsoft Visual Basic 6.0 Service Pack 6";
tag_insight = "The flaw is due to an error in the VBScript and JScript scripting
  engines during handling of certain script requests when using OLE.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-008.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-008.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801703");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-13 17:08:42 +0100 (Thu, 13 Jan 2011)");
  script_cve_id("CVE-2007-0065");
  script_bugtraq_id(27661);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Vulnerability in OLE Automation Could Allow Remote Code Execution (947890)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28902");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Feb/1019373.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-008.mspx");
 
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\system32\oleaut32.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

## Get Version from oleaut32.dll file
dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

## MS08-008 Hotfix (947890)
if(hotfix_missing(name:"947890") == 0){
  exit(0);
}

# Check for existence of Visual Basic
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(item:"DisplayName", key:key + item);
  if("Microsoft Visual Basic" >< appName)
  {
    if(version_in_range(version:dllVer, test_version:"2.40", test_version2:"2.40.4531.9") ||
       version_in_range(version:dllVer, test_version:"2.40", test_version2:"2.40.4519.9") ||
       version_in_range(version:dllVer, test_version:"5.2", test_version2:"5.2.3790.726") ||
       version_in_range(version:dllVer, test_version:"5.2", test_version2:"5.2.3790.3056") ||
       version_in_range(version:dllVer, test_version:"5.2", test_version2:"5.2.3790.4201") ||
       version_in_range(version:dllVer, test_version:"6.0", test_version2:"6.0.6000.20731") ||
       version_in_range(version:dllVer, test_version:"3.50", test_version2:"3.50.5021.9") ||
       version_in_range(version:dllVer, test_version:"5.1", test_version2:"5.1.2600.3265"))
    {
      security_message(0);
      exit(0);
    }
  }
}  

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:2) <= 0){
  exit(0);
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for oleaut32.dll version < 2.40.4532.0
  if(version_is_less(version:dllVer, test_version:"2.40.4532.0")){
      security_message(0);
  }
  exit(0);
}
 
## Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## Grep for oleaut32.dll version < 5.1.2600.3266
    if(version_is_less(version:dllVer, test_version:"5.1.2600.3266")){
           security_message(0);
    }
    exit(0);
  }
}
 
## Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for oleaut32.dll version < 5.2.3790.3057
    if(version_is_less(version:dllVer, test_version:"5.2.3790.3057")){
         security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## Grep for oleaut32.dll version < 5.2.3790.4202
    if(version_is_less(version:dllVer, test_version:"5.2.3790.4202")){
       security_message(0);
    }
    exit(0);
  }
  security_message(0);
}
 
# Windows Vista
else if(hotfix_check_sp(winVista:3) > 0)
{
  # Grep for oleaut32.dll version < 6.0.6000.16607
  if(version_is_less(version:dllVer, test_version:"6.0.6000.16607")){
    security_message(0);
  }
  exit(0);
}
