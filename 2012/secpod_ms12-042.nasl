###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-042.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Windows Kernel Privilege Elevation Vulnerabilities (2711167)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with kernel-mode privileges.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 x64 Edition Service Pack 1 and prior
  Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows 2K3 x32 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 x64 Edition Service Pack 1 and prior";
tag_insight = "The flaws are due to an,
  - Error in the User Mode Scheduler (UMS) when handling a particular system
    request can be exploited to execute arbitrary code.
  - Error in incorrect protection of BIOS ROM can be exploited to execute
    arbitrary code.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-042";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-042.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902916");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0217", "CVE-2012-1515");
  script_bugtraq_id(53856, 52820);
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-13 09:21:39 +0530 (Wed, 13 Jun 2012)");
  script_name("Microsoft Windows Kernel Privilege Elevation Vulnerabilities (2711167)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49454/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2707511");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027155");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-042");

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

sysPath = "";
exeVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4 ,win2003:3, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from ntoskrnl.exe file
exeVer = fetch_file_version(sysPath, file_name:"system32\ntoskrnl.exe");
if(!exeVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Grep for ntoskrnl.exe < 5.1.2600.6223
  if(version_is_less(version:exeVer, test_version:"5.1.2600.6223")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  ## Grep for ntoskrnl.exe version < 5.2.3790.4998
  if(version_is_less(version:exeVer, test_version:"5.2.3790.4998")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7x64:2, win2008r2:2) > 0)
{
  ## Check for ntoskrnl.exe version
  if(version_is_less(version:exeVer, test_version:"6.1.7600.17017") ||
     version_in_range(version:exeVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21206")||
     version_in_range(version:exeVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17834")||
     version_in_range(version:exeVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21986")){
    security_message(0);
  }
}
