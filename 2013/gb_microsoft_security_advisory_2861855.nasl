###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_security_advisory_2861855.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Remote Desktop Protocol Security Advisory (2861855)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "
  Impact Level: System";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803867");
  script_version("$Revision: 9353 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-17 16:25:19 +0530 (Sat, 17 Aug 2013)");
  script_name("Microsoft Remote Desktop Protocol Security Advisory (2861855)");

  tag_summary =
"This host is missing an important security update according to Microsoft
advisory (2861855).";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to security issue in Network-level Authentication (NLA)
method in Remote Desktop Sessions.";

  tag_impact =
"Successful exploitation will allow remote attackers to bypass the security.";

  tag_affected =
"Microsoft Windows 7 x32/x64 Service Pack 1 and prior
Microsoft Windows Vista x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/advisory/2861855";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2861855");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/advisory/2861855");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
sysPath = "";
exeVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Tssecsrv.sys file
exeVer = fetch_file_version(sysPath, file_name:"system32\drivers\tssecsrv.sys");
if(!exeVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Tssecsrv.sys version
  if(version_is_less(version:exeVer, test_version:"6.0.6002.18868") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23139")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Tssecsrv.sys version
  if(version_is_less(version:exeVer, test_version:"6.1.7601.18186") ||
     version_in_range(version:exeVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22360")){
    security_message(0);
  }
  exit(0);
}
