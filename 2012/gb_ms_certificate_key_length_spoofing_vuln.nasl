###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_certificate_key_length_spoofing_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Windows Minimum Certificate Key Length Spoofing Vulnerability (2661254)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to spoof content, perform
  phishing attacks or perform man-in-the-middle attacks.
  Impact Level: System";
tag_affected = "Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "The private keys used in digital certificate with RSA keys less than 1024
  bits in length can be derived and could allow an attacker to duplicate the
  certificates. An duplicate certificate could be used to spoof content,
  perform phishing attacks, or perform man-in-the-middle attacks.";
tag_solution = "Apply the Patch from below link,
  http://technet.microsoft.com/en-us/security/advisory/2661254";
tag_summary = "The host is installed with Microsoft Windows operating system and
  is prone to digital certificate key length spoofing vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803007");
  script_version("$Revision: 9352 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-08-23 16:14:43 +0530 (Thu, 23 Aug 2012)");
  script_name("Microsoft Windows Minimum Certificate Key Length Spoofing Vulnerability (2661254)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2661254");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2661254");
  script_xref(name : "URL" , value : "http://blogs.technet.com/b/rhalbheer/archive/2012/08/14/security-advisory-update-for-minimum-certificate-key-length.aspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
dllVer = "";
sysPath = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Crypt32.dll file
dllVer = fetch_file_version(sysPath, file_name:"system32\Crypt32.dll");
if(!dllVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Check for Crypt32.dll version before 5.131.2600.6239
  if(version_is_less(version:dllVer, test_version:"5.131.2600.6239")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Check for Crypt32.dll version before 5.131.3790.5014
  if(version_is_less(version:dllVer, test_version:"5.131.3790.5014")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Crypt32.dll version
  if(version_is_less(version:dllVer, test_version:"6.0.6002.18643") ||
     version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22868")){
    security_message(0);
  }
  exit(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Crypt32.dll version
  if(version_is_less(version:dllVer, test_version:"6.1.7600.17035") ||
     version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21224")||
     version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17855")||
     version_in_range(version:dllVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22009")){
    security_message(0);
  }
}
