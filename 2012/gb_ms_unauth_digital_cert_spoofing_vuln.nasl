###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_unauth_digital_cert_spoofing_vuln.nasl 10786 2018-08-06 10:01:42Z santu $
#
# Microsoft Unauthorized Digital Certificates Spoofing Vulnerability (2728973)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to use the
  certificates to spoof content, perform phishing attacks, or perform
  man-in-the-middle attacks.
  Impact Level: System";
tag_affected = "Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "Microsoft certificate authorities, which are stored outside the recommended
  secure storage practices can be misused. An attacker could use these
  certificates to spoof content, perform phishing attacks, or perform
  man-in-the-middle attacks.";
tag_solution = "Apply the Patch from below link,
  http://support.microsoft.com/kb/2728973";
tag_summary = "This host is installed with Microsoft Windows operating system and
  is prone to Spoofing vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802912");
  script_version("$Revision: 10786 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-08-06 12:01:42 +0200 (Mon, 06 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-07-12 17:17:25 +0530 (Thu, 12 Jul 2012)");
  script_name("Microsoft Unauthorized Digital Certificates Spoofing Vulnerability (2728973)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2728973");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2728973");

  script_tag(name:"qod_type", value:"registry");
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

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath, file_name:"advpack.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.0.2600.0"))
{
  report = report_fixed_ver(file_checked:sysPath + "\advpack.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.0.2600.0");
  security_message(data:report);
  exit(0);
}
