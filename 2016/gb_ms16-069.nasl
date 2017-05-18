###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-069.nasl 5850 2017-04-04 09:01:03Z teissa $
#
# Microsoft Windows JScript and VBScript Remote Code Execution Vulnerabilities (3163640)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807338");
  script_version("$Revision: 5850 $");
  script_cve_id("CVE-2016-3205", "CVE-2016-3206", "CVE-2016-3207");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-04 11:01:03 +0200 (Tue, 04 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-06-15 08:55:39 +0530 (Wed, 15 Jun 2016)");
  script_name("Microsoft Windows JScript and VBScript Remote Code Execution Vulnerabilities (3163640)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-069.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple remote code execution flaws exist
  in the way that the JScript 9, JScript, and VBScript engines render when
  handling objects in memory in Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently
  logged-in user.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS16-069");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-in/kb/3163640");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-069");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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
dllVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win2008:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

##Fetch the version of Vbscript.dl
dllVer = fetch_file_version(sysPath, file_name:"System32\Vbscript.dll");
if(!dllVer){
  exit(0);
}

if(dllVer =~ "^(5\.7\.6002\.2)"){
  Vulnerable_range = "5.7.6002.23000 - 5.7.6002.23966";
}

else if(dllVer =~ "^(5\.7\.6002\.1)"){
  Vulnerable_range = "Less than 5.7.6002.19652";
}

## Windows Vista and Server 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Vbscript.dll version
  if(version_is_less(version:dllVer, test_version:"5.7.6002.19652") ||
     version_in_range(version:dllVer, test_version:"5.7.6002.23000", test_version2:"5.7.6002.23966"))
  {
    report = 'File checked:     ' + sysPath + "\system32\Vbscript.dll" + '\n' +
             'File version:     ' + dllVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
