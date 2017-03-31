###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms17-020.nasl 5582 2017-03-15 15:50:24Z antu123 $
#
# Microsoft Windows DVD Maker Cross-Site Request Forgery Vulnerability (3208223)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810595");
  script_version("$Revision: 5582 $");
  script_cve_id("CVE-2017-0045");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-15 16:50:24 +0100 (Wed, 15 Mar 2017) $");
  script_tag(name:"creation_date", value:"2017-03-15 08:10:02 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows DVD Maker Cross-Site Request Forgery Vulnerability (3208223)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-020.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"The flaw exists when Windows DVD Maker fails 
  to properly parse a specially crafted '.msdvd' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain information to further compromise a target system.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1.");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS17-020");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3208223");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS17-020");
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
dvdVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, winVistax64:3) <= 0){
  exit(0);
}

## Fetch the version of 'DVDMaker.exe'
## https://www.sevenforums.com/tutorials/54090-windows-dvd-maker-how-use.html
if(!dvdVer = fetch_file_version(sysPath:"C:\Program Files\DVD Maker", file_name:"DVDMaker.exe"))
{
  ## vista
  if(!dvdVer = fetch_file_version(sysPath:"C:\Program Files\Movie Maker", file_name:"DVDMaker.exe")){
    exit(0);
  }
}

## Windows 7
if(hotfix_check_sp(win7:2, win7x64:2) > 0 && dvdVer)
{
  ## Check for DVDMaker.exe version
  ## Presently GDR information is not available.
  if(version_is_less(version:dvdVer, test_version:"6.1.7601.23656"))
  {
    Vulnerable_range = "Less than 6.1.7601.23656";
    VULN1 = TRUE ;
  }
}

## Windows Vista
else if(hotfix_check_sp(winVista:3, winVistax64:3) > 0 && dvdVer)
{
  ## Check for DVDMaker.exe version 
  if(version_is_less(version:dvdVer, test_version:"6.0.6002.19725"))
  {
    Vulnerable_range = "Less than 6.0.6002.19725";
    VULN2 = TRUE ;
  }

  else if(version_in_range(version:dvdVer, test_version:"6.0.6002.24000", test_version2:"6.0.6002.24047"))
  {
    Vulnerable_range = "6.0.6002.24000 - 6.0.6002.24047";
    VULN2 = TRUE ;
  }
}

if(VULN1)
{
  report = 'File checked:     ' + "C:\Program Files\DVD Maker\DVDMaker.exe" + '\n' +
           'File version:     ' + dvdVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN2)
{
  report = 'File checked:     ' + "C:\Program Files\Movie Maker\DVDMaker.exe" + '\n' +
           'File version:     ' + dvdVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
