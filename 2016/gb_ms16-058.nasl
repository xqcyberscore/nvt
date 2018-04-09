###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-058.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# Microsoft Windows IIS Remote Code Execution Vulnerability (3141083)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807323");
  script_version("$Revision: 9381 $");
  script_cve_id("CVE-2016-0152");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-05-11 08:26:16 +0530 (Wed, 11 May 2016)");
  script_name("Microsoft Windows IIS Remote Code Execution Vulnerability (3141083)");

  script_tag(name:"summary", value:"This host is missing a important security
  update according to Microsoft Bulletin MS16-058.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"A remote code execution flaw exists when
  Microsoft Windows fails to properly validate input before loading certain
  libraries.");

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
  https://technet.microsoft.com/library/security/MS16-058");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3141083");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3141083");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-058");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "gb_ms_iis_detect_win.nasl");
  script_mandatory_keys("MS/IIS/Ver");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
dllVer = "";

## Confirm IIS
iisVer = get_kb_item("MS/IIS/Ver");
if(!iisVer){
  exit(0);
}

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win2008:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

##Fetch the version of Aspnetca.exe
dllVer = fetch_file_version(sysPath, file_name:"system32\inetsrv\Aspnetca.exe");
if(!dllVer){
  exit(0);
}

if (dllVer =~ "^(7\.0\.6002\.1)"){
  Vulnerable_range = "Less than 7.0.6002.19634";
}

else if(dllVer =~ "^(7\.0\.6002\.2)"){
  Vulnerable_range = "7.0.6002.23000 - 7.0.6002.23947";
}

## Windows Vista and Server 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Vbscript.dll version
  if((version_is_less(version:dllVer, test_version:"7.0.6002.19634")) ||
     (version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23947")))
  {
    report = 'File checked:     ' + sysPath + "\system32\inetsrv\Aspnetca.exe" + '\n' +
             'File version:     ' + dllVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
