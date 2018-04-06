###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unauth_digital_cert_spoofing_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Windows Unauthorized Digital Certificates Spoofing Vulnerability (2718704)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_affected = "Windows 7 Service Pack 1 and prior
  Windows XP Service Pack 3 and prior
  Windows Vista Service Pack 2 and prior
  Windows Server 2003 Service Pack 2 and prior
  Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is due to unauthorized digital certificates derived from a Microsoft
  Certificate Authority. An unauthorized certificate could be used to spoof
  content, perform phishing attacks, or perform man-in-the-middle attacks.";
tag_solution = "Apply the Patch from below link,
  http://technet.microsoft.com/en-us/security/advisory/2718704";
tag_summary = "The host is installed with Microsoft Windows operating system and
  is prone to digital certificates spoofing vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802634");
  script_version("$Revision: 9352 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-04 14:14:14 +0530 (Mon, 04 Jun 2012)");
  script_name("Microsoft Windows Unauthorized Digital Certificates Spoofing Vulnerability (2718704)");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027114");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2718704");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2718704");
  script_xref(name : "URL" , value : "http://www.theregister.co.uk/2012/06/04/microsoft_douses_flame/print.html");

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
cert = "";
flag = FALSE;

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Untrusted Certificates Path
key = "SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## The invalid certificates and their thumbprints
certs = make_list(
        ## Microsoft Enforced Licensing Intermediate PCA
        "2A83E9020591A55FC6DDAD3FB102794C52B24E70",
        ## Microsoft Enforced Licensing Intermediate PCA
        "3A850044D8A195CD401A680C012CB0A3B5F8DC08",
        ## Microsoft Enforced Licensing Registration Authority CA (SHA1)
        "FA6660A94AB45F6A88C0D7874D89A863D74DEE97"
        );

## Verify that the certificates have been added to the Untrusted Certificates
foreach cert (certs)
{
  if(! registry_key_exists(key: key+cert))
  {
    flag = TRUE;
    break;
  }
}

## File information is not available for Windows 7, Vista and 2008
if(flag && hotfix_check_sp(winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2) > 0)
{
  security_message(0);
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
  ## Check for Crypt32.dll version before 5.131.2600.6237
  if(version_is_less(version:dllVer, test_version:"5.131.2600.6237")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003
else if(hotfix_check_sp(win2003:3, win2003x64:3, xpx64:3) > 0)
{
  ## Check for Crypt32.dll version before 5.131.3790.5012
  if(version_is_less(version:dllVer, test_version:"5.131.3790.5012")){
    security_message(0);
  }
  exit(0);
}
