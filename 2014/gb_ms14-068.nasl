###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-068.nasl 3524 2016-06-15 13:10:28Z benallard $
#
# MS Windows Kerberos Checksum Remote Privilege Escalation Vulnerability (3011780)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804799");
  script_version("$Revision: 3524 $");
  script_cve_id("CVE-2014-6324");
  script_bugtraq_id(70958);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 15:10:28 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-11-19 12:57:43 +0530 (Wed, 19 Nov 2014)");
  script_name("MS Windows Kerberos Checksum Remote Privilege Escalation Vulnerability (3011780)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-068.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"Vulnerability exists when Microsoft Kerberos
  KDC implementations fail to properly validate signatures.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to escalate the privileges.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"
  Microsoft Windows 8 x32/x64
  Microsoft Windows Server 2012/R2
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name: "solution" , value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  link, https://technet.microsoft.com/en-us/security/bulletin/ms14-068");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/213119");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3011780");
  script_xref(name:"URL", value:"http://technet.microsoft.com/security/bulletin/MS14-068");
  script_xref(name:"URL", value:"http://blogs.technet.com/b/srd/archive/2014/11/18/additional-information-about-cve-2014-6324.aspx");

  script_summary("Check for the vulnerable 'System.Runtime.Remoting.dll' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
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
if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

##Get the Kerberos.dll version
dllVer = fetch_file_version(sysPath, file_name:"system32\Kerberos.dll");
if(!dllVer){
  exit(0);
}

## Windows 2003
if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_is_less(version:dllVer, test_version:"5.2.3790.5467")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.19219")||
     version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23526")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Server 2008r2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"6.1.7601.18000", test_version2:"6.1.7601.18657")||
     version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22864")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and Server 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.17171")||
     version_in_range(version:dllVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21288")){
    security_message(0);
  }
  exit(0);
}

## Windows 8.1 and Server 2012 R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Mshtml.dll version
  if(version_is_less(version:dllVer, test_version:"6.3.9600.17423")){
    security_message(0);
  }
  exit(0);
}
