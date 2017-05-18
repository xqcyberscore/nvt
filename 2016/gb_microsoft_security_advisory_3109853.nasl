###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_security_advisory_3109853.nasl 5782 2017-03-30 09:01:05Z teissa $
#
# Microsoft TLS Session Resumption Interoperability Improvement Advisory (3109853)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806662");
  script_version("$Revision: 5782 $");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-30 11:01:05 +0200 (Thu, 30 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-14 11:12:27 +0530 (Thu, 14 Jan 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft TLS Session Resumption Interoperability Improvement Advisory (3109853)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft advisory (3109853).");

  script_tag(name: "vuldetect" , value: "Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value: "An update is available that improve
  interoperability between Schannel-based TLS clients and 3rd-party TLS servers
  that enable RFC5077-based resumption and that send the NewSessionTicket message
  in the abbreviated TLS handshake.");

  script_tag(name: "impact" , value: "Successful exploitation will allow
  attackers to perform a fallback to a lower TLS protocol version than the one
  that would have been negotiated and conduct further attacks.

  Impact Level: System");

  script_tag(name: "affected" , value:"
  Windows Server 2012 R2
  Microsoft Windows 10 x32/x64
  Microsoft Windows 8 x32/x64
  Microsoft Windows Server 2012
  Microsoft Windows 8.1 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64.");

  script_tag(name: "solution" , value: "Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/en-us/library/security/3109853");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3109853");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/3109853");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows");
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
if(hotfix_check_sp(win8:1, win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from 'Schannel.dll' file
dllVer = fetch_file_version(sysPath, file_name:"system32\schannel.dll");
dllVer1 = fetch_file_version(sysPath, file_name:"SysWOW64\schannel.dll");
if(dllVer1){
  schpPath64 = sysPath + "\SysWOW64\schannel.dll";
}

if(!dllVer && !dllVer1){
  exit(0);
}

##Windows 8 x86
if(hotfix_check_sp(win8:1) > 0 && dllVer)
{
  ## Check for schannel.dll version
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17592"))
  {
    Vulnerable_range = "Version Less than - 6.2.9200.17592";
    VULN = TRUE ;
  }

  else if(version_in_range(version:dllVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21707"))
  {
    Vulnerable_range = "6.2.9200.21000 - 6.2.9200.21707";
    VULN = TRUE ;
  }
}

##Windows 8  and Windows 2012 x64
else if(hotfix_check_sp(win8x64:1, win2012:1) > 0 && dllVer1)
{
  ## Check for schannel.dll version
  if(version_is_less(version:dllVer1, test_version:"6.2.9200.17590"))
  {
    report = 'File checked:     ' + schpPath64 + '\n' +
             'File version:     ' + dllVer1  + '\n' +
             'Vulnerable range:  Less than 6.2.9200.17590\n' ;
    security_message(data:report);
    exit(0);
  }
  else if(version_in_range(version:dllVer1, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21707"))
  {
    report = 'File checked:     ' + schpPath64 + '\n' +
             'File version:     ' + dllVer1  + '\n' +
             '6.2.9200.21000 - 6.2.9200.21707\n' ;
    security_message(data:report);
    exit(0);
  }
}

## Win 8.1 and 2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && dllVer)
{
  ## Check for schannel.dll version
  if(version_is_less(version:dllVer, test_version:"6.3.9600.18154"))
  {
    Vulnerable_range = "Version Less than - 6.3.9600.18154";
    VULN = TRUE ;
  }
}

## Windows 10
else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && dllVer)
{
  ## Windows 10 Core
  ## Check for schannel.dll version
  if(version_is_less(version:dllVer, test_version:"10.0.10240.16644"))
  {
    Vulnerable_range = "Less than 10.0.10240.16644";
    VULN = TRUE ;
  }
  ## Windows 10 version 1511
  ## Check for schannel.dll version
  else if(version_in_range(version:dllVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.62"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.62";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\schannel.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
