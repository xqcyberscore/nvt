###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-032.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Windows OpenType Compact Font Format (CFF) Driver Remote Code Execution Vulnerability (2507618)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers execute arbitrary code
  via a malicious OpenType font, or by local attackers to gain elevated
  privileges.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is caused by a stack overflow error in the OpenType Compact Font
  Format (CFF) driver when handling parameter values of OpenType fonts.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS11-032.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-032.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902363");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0034");
  script_bugtraq_id(47179);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Windows OpenType Compact Font Format (CFF) Driver Remote Code Execution Vulnerability (2507618)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43836/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0950");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS11-032.mspx");

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
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-032 Hotfix
if((hotfix_missing(name:"2507618") == 0)){
  exit(0);
}

## Get System32 path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath, file_name:"system32\Atmfd.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(xp:4, winVista:3, win2008:3) > 0)
{
  # Grep for Atmfd.dll version < 5.1.2.232
  if(version_is_less(version:dllVer, test_version:"5.1.2.232"))
  {
    security_message(0);
    exit(0);
  }
}

if(hotfix_check_sp(win7:2) > 0)
{
  # Grep for Atmfd.dll version < 5.1.2.234
  if(version_is_less(version:dllVer, test_version:"5.1.2.234"))
  {
    security_message(0);
    exit(0);
  }
}

if(hotfix_check_sp(win2003:3) > 0)
{
  # Grep for Atmfd.dll version < 5.2.2.232
  if(version_is_less(version:dllVer, test_version:"5.2.2.232")){
    security_message(0);
  }
}
