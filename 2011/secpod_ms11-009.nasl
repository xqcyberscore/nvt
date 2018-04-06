###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-009.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft JScript and VBScript Scripting Engines Information Disclosure Vulnerability (2475792)
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

tag_impact = "Successful exploitation will allow remote attackers to gain access to
  sensitive information that may aid in further attacks.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior";
tag_insight = "The flaw is caused by a memory corruption error in the JScript and VBScript
  scripting engines when processing scripts in Web pages.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms11-009";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-009.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902336");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_cve_id("CVE-2011-0031");
  script_bugtraq_id(46139);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Microsoft JScript and VBScript Scripting Engines Information Disclosure Vulnerability (2475792)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43249/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0322");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-009");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
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

ieVer = "";
sysPath = "";
dllVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

## Get IE Version from KB
ieVer = get_kb_item("MS/IE/Version");
if(ieVer && (ieVer =~ "9")){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(! sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath, file_name:"System32\Vbscript.dll");
if(!dllVer){
  exit(0);
}

## Check for Vbscript.dll version
if(version_is_less(version:dllVer, test_version:"5.8.7600.16732")||
   version_in_range(version:dllVer, test_version:"5.8.7600.20000", test_version2:"5.8.7600.20872")||
   version_in_range(version:dllVer, test_version:"5.8.7601.17000", test_version2:"5.8.7601.17534")||
   version_in_range(version:dllVer, test_version:"5.8.7601.21000", test_version2:"5.8.7601.21633")){
  security_message(0);
}
