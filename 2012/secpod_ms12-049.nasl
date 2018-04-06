###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-049.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Windows TLS Protocol Information Disclosure Vulnerability (2655992)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow an attacker to gain access to sensitive
  information that may aid in further attacks.
  Impact Level: System";
tag_affected = "Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "Microsoft Windows contains a flaw related to the Transport Layer Security
  (TLS) Handshake Protocol when the Cipher-block chaining (CBC) mode of
  operation is used. This flaw may allow a remote attacker to gain access to
  decrypted traffic.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-049";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-049.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902846");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(54304);
  script_cve_id("CVE-2012-1870");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-11 10:10:10 +0530 (Wed, 11 Jul 2012)");
  script_name("Microsoft Windows TLS Protocol Information Disclosure Vulnerability (2655992)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49874");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2655992");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027233");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-049");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
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
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(! sysPath){
  exit(0);
}

## Get Version from Schannel.dll file
dllVer = fetch_file_version(sysPath, file_name:"system32\Schannel.dll");
if(! dllVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Check for Schannel.dll version before 5.1.2600.6239
  if(version_is_less(version:dllVer, test_version:"5.1.2600.6239")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Check for Schannel.dll version before 5.2.3790.5014
  if(version_is_less(version:dllVer, test_version:"5.2.3790.5014")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Schannel.dll version
  if(version_is_less(version:dllVer, test_version:"6.0.6002.18643") ||
     version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22868")){
    security_message(0);
  }
  exit(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Schannel.dll version
  if(version_is_less(version:dllVer, test_version:"6.1.7600.17035") ||
     version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21224")||
     version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17855")||
     version_in_range(version:dllVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22009")){
    security_message(0);
  }
}
