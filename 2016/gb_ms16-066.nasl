###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-066.nasl 5580 2017-03-15 10:00:34Z teissa $
#
# Microsoft Windows Virtual Secure Mode Security Feature Bypass vulnerability (3155451)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807693");
  script_version("$Revision: 5580 $");
  script_cve_id("CVE-2016-0181");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-15 11:00:34 +0100 (Wed, 15 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-05-11 19:18:46 +0530 (Wed, 11 May 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Virtual Secure Mode Security Feature Bypass vulnerability (3155451)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-066.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and 
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"A security feature bypass vulnerability exists
  when Windows incorrectly allows certain kernel-mode pages to be marked as Read, Write,
  Execute (RWX) even with Hypervisor Code Integrity (HVCI) enabled."); 

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to bypass a security feature.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/en-us/library/security/MS16-066");

  script_tag(name:"solution_type", value:"VendorFix");
  
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-in/kb/3156387");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-in/kb/3156421");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/MS16-066");

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
sysVer = fetch_file_version(sysPath, file_name:"System32\Edgehtml.dll");
if(!sysVer){
  exit(0);
}

##Windows 10
if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  ## Check for Edgehtml.dll version
  if(version_is_less(version:sysVer, test_version:"11.0.10240.16841"))
  {
    Vulnerable_range = "Less than 11.0.10240.16841";
    VULN = TRUE ;
  }
  ##Windows 10 Version 1511
  else if(version_in_range(version:sysVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.305"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.305";
    VULN = TRUE ;
  }
}

  
if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Edgehtml.dll" + '\n' +
           'File version:     ' + sysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
