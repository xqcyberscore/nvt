###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4026059.nasl 6757 2017-07-19 05:57:31Z cfischer $
#
# Microsoft Windows CLFS Elevation of Privilege Vulnerability (KB4026059)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811223");
  script_version("$Revision: 6757 $");
  script_cve_id("CVE-2017-8590");
  script_bugtraq_id(99427);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 07:57:31 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-07-12 08:48:33 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft Windows CLFS Elevation of Privilege Vulnerability (KB4026059)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4026059");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists when the Windows Common Log
  File System (CLFS) driver improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to run processes in an elevated context. 

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/4026059");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4026059");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
fileVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

##Fetch the version of 'clfs.sys'
fileVer = fetch_file_version(sysPath, file_name:"clfs.sys");
if(!fileVer){
  exit(0);
}

## Check for clfs.sys version
if(version_is_less(version:fileVer, test_version:"6.0.6002.19810"))
{
  Vulnerable_range = "Less than 6.0.6002.19810";
  VULN = TRUE ;
}

else if(version_in_range(version:fileVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24129"))
{
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24129";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\clfs.sys" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
