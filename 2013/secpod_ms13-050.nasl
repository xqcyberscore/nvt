###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-050.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Windows Print Spooler Components Privilege Escalation Vulnerability (2839894)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  code with system privileges, resulting in complete compromise of the target.
  Impact Level: System";

tag_affected = "Microsoft Windows 8
  Microsoft Windows Server 2012
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "The vulnerability is caused due to improper memory operations performed by
  the affected software when deleting printer connections.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  https://technet.microsoft.com/en-us/security/bulletin/ms13-050";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-050.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903212");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1339");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-06-12 09:16:20 +0530 (Wed, 12 Jun 2013)");
  script_name("Microsoft Windows Print Spooler Components Privilege Escalation Vulnerability (2839894)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53742");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2839894");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-050");
  script_xref(name : "URL" , value : "http://tools.cisco.com/security/center/viewAlert.x?alertId=29560");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
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

## Variable Initialization
sysPath = "";
exeVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
   win8:1, win2012:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Win32spl.dll file
exeVer = fetch_file_version(sysPath, file_name:"system32\Win32spl.dll");
if(!exeVer){
  exit(0);
}

## Windows 7 and Windows 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Win32spl.dll version
  if(version_is_less(version:exeVer, test_version:"6.1.7601.18142") ||
     version_in_range(version:exeVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22310")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:exeVer, test_version:"6.0.6002.18832") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23102")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and Windows Server 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
## Check for Win32k.sys version
if(version_is_less(version:exeVer, test_version:"6.2.9200.16598") ||
   version_in_range(version:exeVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20701")){
     security_message(0);
  }
  exit(0);
}
