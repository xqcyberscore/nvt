###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_security_advisory_2914486.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Windows Kernel Privilege Escalation Vulnerability (2914368)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Updated by: Antu Sanadi <santu@secpod.com>
# Updated according ms14-002
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803971");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-5065");
  script_bugtraq_id(63971);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-12-02 15:40:48 +0530 (Mon, 02 Dec 2013)");
  script_name("Microsoft Windows Kernel Privilege Escalation Vulnerability (2914368)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS14-002";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is  due to an input validation error within the NDPROXY (NDProxy.sys)
kernel component and can be exploited to execute arbitrary code with kernel
privileges.";

  tag_impact =
"Successful exploitation will allow remote attackers to gain escalated
privileges.

Impact Level: System";

  tag_affected =
"Microsoft Windows XP x32 Edition Service Pack 3 and prior
Microsoft Windows XP x64 Edition Service Pack 2 and prior
Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior ";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-002";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/55809");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2914368");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms14-002");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/advisory/2914486");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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
win32SysVer="";


## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

win32SysVer = fetch_file_version(sysPath, file_name:"system32\drivers\Ndproxy.sys");
if(!win32SysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Grep for the file version
  if(version_is_less(version:win32SysVer, test_version:"5.1.2600.6484")){
    security_message(0);
  }
  exit(0);
}

## Windows XP Professional x64 edition and Windows Server 2003
if(hotfix_check_sp(xpx64:3,win2003x64:3,win2003:3) > 0)
{
  ## Grep for the file version
  if(version_is_less(version:win32SysVer, test_version:"5.2.3790.5263")){
    security_message(0);
  }
  exit(0);
}
