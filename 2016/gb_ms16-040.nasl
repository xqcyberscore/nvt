###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-040.nasl 5745 2017-03-28 09:01:00Z teissa $
#
# MS Windows XML Core Services Remote Code Execution Vulnerability (3148541)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807539");
  script_version("$Revision: 5745 $");
  script_cve_id("CVE-2016-0147");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-28 11:01:00 +0200 (Tue, 28 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-04-13 08:13:24 +0530 (Wed, 13 Apr 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS Windows XML Core Services Remote Code Execution Vulnerability (3148541)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-040.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Flaw exists due to some unspecified error
  when XML Core services parser processes user input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run malicious code remotely to take control of the user's system.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows 8.1 x32/x64
  Microsoft Windows 10 x32/x64
  Microsoft Windows Server 2012
  Microsoft Windows Server 2012 R2
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS15-040");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/3146963");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-040");

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
mssysPath = "";
msdllVer="";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win10:1, win10x64:1,
                   win2008:3, win2008r2:2, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

## Get System Path
mssysPath = smb_get_systemroot();
if(!mssysPath ){
  exit(0);
}

msdllVer = fetch_file_version(sysPath:mssysPath, file_name:"system32\Msxml3.dll");
if(!msdllVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Msxml3.dll version
  if(version_is_less(version:msdllVer, test_version:"8.100.5013.0"))
  {
    Vulnerable_range = "Less than 8.100.5013.0";
    VULN = TRUE ;
  }
}

## Windows 7 and Windows Server 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Msxml3.dll version
  ## GDR info not given
  if(version_is_less(version:msdllVer, test_version:"8.110.7601.23373"))
  {
    Vulnerable_range = "Less than 8.110.7601.23373";
    VULN = TRUE ;
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Msxml3.dll version
  if(version_is_less(version:msdllVer, test_version:"8.110.9600.18258"))
  {
    Vulnerable_range = "Less than 8.110.9600.18258";
    VULN = TRUE ;
  }
}

## Windows 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  ## Check for Msxml3.dll version
  ## GDR info not given
  if(version_is_less(version:msdllVer, test_version:"8.110.9200.21793"))
  {
    Vulnerable_range = "Less than 8.110.9200.21793";
    VULN = TRUE ;
  }
}

## Windows 10
else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  ## Windows 10 Core
  ## Check for Msxml3.dll version
  if(version_is_less(version:msdllVer, test_version:"8.110.10240.16766"))
  {
    Vulnerable_range4 = "Less than 8.110.10240.16766";
    VULN = TRUE ;
  }

  ## Windows 10 version 1511
  ## Check for Msxml3.dll version
  else if(version_in_range(version:msdllVer, test_version:"8.110.10586.0", test_version2:"8.110.10586.211"))
  {
    Vulnerable_range = "8.110.10586.0 - 8.110.10586.211";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + mssysPath + "\System32\Msxml3.dll" + '\n' +
           'File version:     ' + msdllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
}

