###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-059.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Data Access Components Remote Code Execution Vulnerabilities (2560656)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attacker to execute arbitrary code
  by tricking a user into opening a Microsoft Excel file (.xlsx) located on a
  remote WebDAV or SMB share.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior.";
tag_insight = "The flaws are due when the Windows Data Access Tracing component incorrectly
  restricts the path used for loading external libraries.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms11-059.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-059.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900294");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_bugtraq_id(49026);
  script_cve_id("CVE-2011-1975");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Data Access Components Remote Code Execution Vulnerabilities (2560656)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45246");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2560656");
  script_xref(name : "URL" , value : "http://www.sophos.com/support/knowledgebase/article/113981.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms11-059.mspx");

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

## MS11-043 Hotfix (2560656)
if(hotfix_missing(name:"2560656") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Odbcjt32.dll file
sysVer = fetch_file_version(sysPath, file_name:"system32\Odbcjt32.dll");
if(!sysVer){
  exit(0);
}

## Windows 7
if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Odbcjt32.dll version
  if(version_in_range(version:sysVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16832")||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20986")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17631")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21746")){
    security_message(0);
  }
}
