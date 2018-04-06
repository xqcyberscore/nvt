###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-008.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2660465)
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

tag_impact = "Successful exploitation could allow remote attackers to cause a denial of
  service and possibly execute arbitrary code with kernel-level privileges.

  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior.

  Microsoft Windows XP Service Pack 3 and prior.

  Microsoft Windows 2003 Service Pack 2 and prior.

  Microsoft Windows Vista Service Pack 2 and prior.

  Microsoft Windows Server 2008 Service Pack 2 and prior.";
tag_insight = "Multiple flaws are due to

  - An error in win32k.sys when validating input passed from user mode through
    the kernel component of GDI can be exploited to corrupt memory via a
    specially crafted web page containing an IFRAME with an overly large
    'height' attribute viewed using the Apple Safari browser.

  - A use-after-free error in win32k.sys when handling certain keyboard layouts
    can be exploited to dereference already freed memory and gain escalated
    privileges.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,

  http://technet.microsoft.com/en-us/security/bulletin/ms12-008";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-008.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902810");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0154", "CVE-2011-5046");
  script_bugtraq_id(51122, 51920);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-15 09:09:09 +0530 (Wed, 15 Feb 2012)");
  script_name("Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2660465)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47237");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2660465");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71873");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18275");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-008");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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

## Variables Initialization
sysPath = "";
sysVer = NULL;

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS12-008 Hotfix (2660465)
if(hotfix_missing(name:"2660465") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(! sysPath){
  exit(0);
}

## Get Version from Win32k.sys file
sysVer = fetch_file_version(sysPath, file_name:"system32\Win32k.sys");
if(! sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Check for Win32k.sys version before 5.1.2600.6188
  if(version_is_less(version:sysVer, test_version:"5.1.2600.6188")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  ## Check for Win32k.sys version before 5.2.3790.4953
  if(version_is_less(version:sysVer, test_version:"5.2.3790.4953")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:sysVer, test_version:"6.0.6002.18569") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22776")){
    security_message(0);
  }
  exit(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16948") ||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21126")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17761")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21897")){
    security_message(0);
  }
}
