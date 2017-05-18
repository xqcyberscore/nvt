###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-113.nasl 5732 2017-03-27 09:00:59Z teissa $
#
# Microsoft Windows Secure Kernel Mode Information Disclosure Vulnerability (3185876)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809311");
  script_version("$Revision: 5732 $");
  script_cve_id("CVE-2016-3344");
  script_bugtraq_id(92855);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-27 11:00:59 +0200 (Mon, 27 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-09-14 08:50:02 +0530 (Wed, 14 Sep 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Secure Kernel Mode Information Disclosure Vulnerability (3185876)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-113.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and 
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"An information disclosure flaw exists when
  Windows Secure Kernel Mode improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to read sensitive information on the target system.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/en-us/library/security/MS16-113");

  script_tag(name:"solution_type", value:"VendorFix");
  
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3185611");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3185614");  
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-113");

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
if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

##Fetch the version of 'Edgehtml.dll'
edgeVer = fetch_file_version(sysPath, file_name:"System32\Edgehtml.dll");
if(!edgeVer){
  exit(0);
}

##Windows 10
if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  ## Check for Edgehtml.dll version
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17113"))
  {
    Vulnerable_range = "Less than 11.0.10240.17113";
    VULN = TRUE ;
  }
  ##Windows 10 Version 1511
  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.588"))  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.588";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
