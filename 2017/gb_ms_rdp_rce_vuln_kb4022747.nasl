###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_rdp_rce_vuln_kb4022747.nasl 6618 2017-07-07 14:17:52Z cfischer $
#
# Microsoft Windows RDP Remote Code Execution Vulnerability (KB4022747)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811205");
  script_version("$Revision: 6618 $");
  script_cve_id("CVE-2017-0176");
  script_bugtraq_id(98752);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-07 16:17:52 +0200 (Fri, 07 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-06-16 10:45:29 +0530 (Fri, 16 Jun 2017)");
  script_name("Microsoft Windows RDP Remote Code Execution Vulnerability (KB4022747)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4022747");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the RDP
  server having Smart Card authentication enabled which fails to handle certain
  requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of current user.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows XP SP2 x64

  Microsoft Windows XP SP3 x86

  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior.");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/4022747");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4022747");
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
winVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

## Fetch the version of 'Gpkcsp.dll'
winVer = fetch_file_version(sysPath, file_name:"Gpkcsp.dll");
if(!winVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Check for Gpkcsp.dll version
  if(version_is_less(version:winVer, test_version:"5.1.2600.7264"))
  {
    Vulnerable_range = "Less than 5.1.2600.7264";
    VULN = TRUE ;
  }
}

## Windows 2003, Windows XP SP2 64bit
else if(hotfix_check_sp(win2003:3, win2003x64:3, xpx64:3) > 0)
{
  ## Check for Gpkcsp.dll version
  if(version_is_less(version:winVer, test_version:"5.2.3790.6093"))
  {
    Vulnerable_range = "Less than 5.2.3790.6093";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\Gpkcsp.dll" + '\n' +
           'File version:     ' + winVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
