###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_kb4014661.nasl 5945 2017-04-12 15:37:08Z antu123 $
#
# Microsoft Internet Explorer Remote Code Execution Vulnerability (KB4014661)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810853");
  script_version("$Revision: 5945 $");
  script_cve_id("CVE-2017-0201");
  script_bugtraq_id(97454);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-12 17:37:08 +0200 (Wed, 12 Apr 2017) $");
  script_tag(name:"creation_date", value:"2017-03-15 12:07:36 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Internet Explorer Remote Code Execution Vulnerability (KB4014661)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft security updates KB4014661.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists in the way that the JScript
  and VBScript engines render when handling objects in memory in Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code in the context of the current user.
 
  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Microsoft Internet Explorer version 9.x");

  script_tag(name: "solution" , value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  https://support.microsoft.com/en-us/help/4014661/cumulative-security-update-for-internet-explorer-april-11-2017");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4014661");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
iePath = "";
iedllVer  = NULL;

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) <= 0){
  exit(0);
}

##Get IE Version
ieVer = get_app_version(cpe:CPE);
if(!ieVer || !(ieVer =~ "^(9)")){
  exit(0);
}

## Get System Path
iePath = smb_get_system32root();
if(!iePath ){
  exit(0);
}

## Get Version from Mshtml.dll
iedllVer = fetch_file_version(sysPath:iePath, file_name:"Mshtml.dll");
if(!iedllVer){
  exit(0);
}

## Windows Vista and Server 2008
if(hotfix_check_sp(winVista:3, win2008:3, winVistax64:3, win2008x64:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:iedllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16871"))
  {
    Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16871";
    VULN = TRUE ;
  }
  else if(version_in_range(version:iedllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20985"))
  {
    Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20985";
    VULN = TRUE ;
  }

  if(VULN)
  {
    report = 'File checked:     ' + iePath + "\Mshtml.dll" + '\n' +
             'File version:     ' + iedllVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);
