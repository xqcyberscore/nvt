###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-084.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Windows Kernel-Mode Drivers Remote Code Execution Vulnerability (2617657)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow local attackers to gain elevated
  privileges or to run arbitrary code in kernel mode and take complete control
  of an affected system. An attacker could then install programs view, change,
  or delete data or create new accounts with full administrative rights.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior";
tag_insight = "The flaw is due to an array-indexing error in 'Win32k.sys' when
  parsing TrueType font files, which can be exploited by attackers to cause
  a denial of service.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms11-084";
tag_summary = "This host has moderate security update missing according to
  Microsoft Bulletin MS11-084.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902485");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-2004");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-09 09:06:04 +0530 (Wed, 09 Nov 2011)");
  script_name("Windows Kernel-Mode Drivers Remote Code Execution Vulnerability (2617657)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46751");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2617657");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-084");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
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

## Check for OS and Service Pack
if(hotfix_check_sp(win7:2) <= 0){
  exit(0);
}

## MS11-084 Hotfix (2617657)
if(hotfix_missing(name:"2617657") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from Win32k.sys file
sysVer = fetch_file_version(sysPath, file_name:"system32\Win32k.sys");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Win32k.sys version
  if(version_in_range(version:sysVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16888")||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21059")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17696")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21827")){
    security_message(0);
  }
}
