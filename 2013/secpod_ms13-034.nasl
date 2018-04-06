###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-034.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Antimalware Client Privilege Elevation Vulnerability (2823482)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the security context of the LocalSystem account.
  Impact Level: System";

tag_affected = "Windows Defender for Windows 8";
tag_insight = "Flaw is due to an unspecified error when improper pathnames are used
  by Windows Defender (Microsoft Antimalware Client).";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-034";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-034.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901216");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-0078");
  script_bugtraq_id(58847);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-04-10 10:20:16 +0530 (Wed, 10 Apr 2013)");
  script_name("Microsoft Antimalware Client Privilege Elevation Vulnerability (2823482)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52921");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2781197");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-034");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
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

## Variable Initialization
key = "";
defender_ver = "";
program_files_path = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win8:1)<=0){
  exit(0);
}

## Windows Defender Key exists
key = "SOFTWARE\Microsoft\Windows Defender";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get Program Files Dir Path
program_files_path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                                     item:"ProgramFilesDir");
if(!program_files_path){
  exit(0);
}

## Get Version from MSASCui.exe file
defender_ver = fetch_file_version(sysPath:program_files_path,
                				  file_name:"Windows Defender\MSASCui.exe");
if(!defender_ver){
  exit(0);
}

## Check for MSASCui.exe version
if(version_is_less(version:defender_ver, test_version:"4.2.223.0"))
{
  security_message(0);
  exit(0);
}
