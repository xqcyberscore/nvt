###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-011.nasl 5534 2017-03-10 10:00:33Z teissa $
#
# Microsoft Edge Multiple Vulnerabilities (3134225)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807063");
  script_version("$Revision: 5534 $");
  script_cve_id("CVE-2016-0077", "CVE-2016-0080", "CVE-2016-0060", "CVE-2016-0061",
                "CVE-2016-0062", "CVE-2016-0084");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-10 11:00:33 +0100 (Fri, 10 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-02-10 09:02:28 +0530 (Wed, 10 Feb 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge Multiple Vulnerabilities (3134225)");

  script_tag(name: "summary" , value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-011.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,
  - Multiple improper memory object handling errors.
  - Mishandling of exceptions when dispatching certain window messages.
  - Microsoft browser does not properly parse HTTP responses.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, bypass the Address Space Layout Randomization 
  (ASLR) security feature,  which helps protect users from a broad class of 
  vulnerabilities and to conduct spoofing attacks and perform unauthorized actions; 
  other attacks are also possible.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"
  Microsoft Edge on Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name: "solution" , value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  link, https://technet.microsoft.com/library/security/MS16-011");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3134225");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-011");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_detect.nasl");
  script_mandatory_keys("MS/Edge/Installed");
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

## Get Version from Mshtml.dll
dllVer = fetch_file_version(sysPath, file_name:"system32\edgehtml.dll");
if(!dllVer){
  exit(0);
}

## Windows Vista 10
if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  ## Check for edgehtml.dll version
  ## Windows 10 Core
  if(version_is_less(version:dllVer, test_version:"11.0.10240.16683"))
  {
    Vulnerable_range = "Less than 11.0.10240.16683";
    VULN = TRUE ;
  }

  ## Check for edgehtml.dll version
  ## Windows 10 version 1511
  else if(version_in_range(version:dllVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.102"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.102";
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
