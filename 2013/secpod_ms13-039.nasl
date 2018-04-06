###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-039.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Windows 'HTTP.sys' Denial of Service Vulnerability (2829254)
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

tag_impact = "Successful exploitation will allow remote attackers to trigger an infinite
  loop and cause denial of service condition.
  Impact Level: System";

tag_affected = "Microsoft Windows 8
  Microsoft Windows Server 2012";
tag_insight = "Flaw is due to an error within the HTTP protocol stack (HTTP.sys) when handling
  HTTP headers.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  https://technet.microsoft.com/en-us/security/bulletin/ms13-039";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-039.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903209");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1305");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-15 09:45:43 +0530 (Wed, 15 May 2013)");
  script_name("Microsoft Windows 'HTTP.sys' Denial of Service Vulnerability (2829254)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2829254");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/53340");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-039");
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

## Variables Initialization
sysPath = "";
httpVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win8:1, win2012:1) <= 0){
#  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from Win32k.sys file
httpVer = fetch_file_version(sysPath, file_name:"system32\drivers\http.sys");
if(!httpVer){
  exit(0);
}

## Windows 8 and Windows Server 2012
if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
 ## Check for Win32k.sys version
  if(version_is_less(version:httpVer, test_version:"6.2.9200.16556") ||
     version_in_range(version:httpVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20659"))
  {
    security_message(0);
    exit(0);
  }
}
