###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-103.nasl 5598 2017-03-17 10:00:43Z teissa $
#
# Microsoft ActiveSyncProvider Universal Outlook Information Disclosure Vulnerability (3182332)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808292");
  script_version("$Revision: 5598 $");
  script_cve_id("CVE-2016-3312");
  script_bugtraq_id(92307);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-17 11:00:43 +0100 (Fri, 17 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-08-10 08:32:49 +0530 (Wed, 10 Aug 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft ActiveSyncProvider Universal Outlook Information Disclosure Vulnerability (3182332)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-103.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"The flaw is due to a failure to establish
  a secure connection by the Universal Outlook feature installed on Microsoft
  Windows.");

  script_tag(name: "impact" , value:"Successful exploitation will allow an
  unauthenticated, remote attacker to access sensitive information.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"
  Microsoft Windows 10 x32/x64
  Windows 10 Version 1511 32-bit/64-bit.");

  script_tag(name: "solution" , value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  link, https://technet.microsoft.com/library/security/MS16-103");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3182332");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-103");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
dllVer  = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Edgehtml.dll
dllVer = fetch_file_version(sysPath, file_name:"system32\edgehtml.dll");
if(!dllVer){
  exit(0);
}

## Windows 10
if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  ## Windows 10 Core
  ## Check for Edgehtml.dll version
  if(version_is_less(version:dllVer, test_version:"11.0.10240.17071"))
  {
    Vulnerable_range = "Less than 11.0.10240.17071";
    VULN = TRUE ;
  }
  ## Windows 10 Version 1511
  ## Check for Edgehtml.dll version
  else if(version_in_range(version:dllVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.544"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.544";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\edgehtml.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

