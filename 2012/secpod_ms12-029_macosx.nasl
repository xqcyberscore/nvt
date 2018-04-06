###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-029_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Office Word Remote Code Execution Vulnerability-2680352 (Mac OS X)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted word document.
  Impact Level: System/Application";
tag_affected = "Microsoft Office 2008 for Mac
  Microsoft Office 2011 for Mac";
tag_insight = "The flaw is due to an error when parsing Rich Text Format (RTF) data
  and can be exploited to corrupt memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS12-029";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-029.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902912");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0183");
  script_bugtraq_id(53344);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-09 13:43:53 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerability-2680352 (Mac OS X)");
  script_xref(name : "URL" , value : "http://krebsonsecurity.com/tag/cve-2012-0183/");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS12-029");
  script_xref(name : "URL" , value : "http://www.symantec.com/security_response/vulnerability.jsp?bid=53344");

  script_copyright("Copyright (C) 2012 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_require_keys("MS/Office/MacOSX/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
offVer = "";

## Get the version from KB
offVer = get_kb_item("MS/Office/MacOSX/Ver");
if(!offVer){
  exit(0);
}

## Check for Office Version 2008(12.3.2) and 2011 (14.2.1)
if(version_in_range(version:offVer, test_version:"12.0", test_version2:"12.3.2")||
   version_in_range(version:offVer, test_version:"14.0", test_version2:"14.2.1")){
  security_message(0);
}
