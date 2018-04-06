###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-026_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# MS Office Outlook Information Disclosure Vulnerability - 2813682 (Mac OS X)
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

tag_impact = "Successful exploitation will allow attackers to gain access to potentially
  sensitive information and that may aid in further attacks.
  Impact Level: Application";

tag_affected = "Microsoft Office 2008 on Mac OS X
  Microsoft Office 2011 on Mac OS X";
tag_insight = "The flaw is due to Microsoft Outlook for Mac loading certain tags when
  previewing an HTML email, which can be exploited to load content from a
  remote server and confirm the existence of the targeted email accounts.";
tag_solution = "Apply the patch from below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-026";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-026.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903201");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-0095");
  script_bugtraq_id(58333);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-13 11:30:32 +0530 (Wed, 13 Mar 2013)");
  script_name("MS Office Outlook Information Disclosure Vulnerability - 2813682 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52559");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/82400");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS13-026");

  script_copyright("Copyright (C) 2013 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
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

## check the version from KB
if(!offVer || !(offVer =~ "^(12|14)")){
  exit(0);
}

## Check for Office Version 2008(12.3.5) and 2011 (14.3.1)
if(version_in_range(version:offVer, test_version:"12.0", test_version2:"12.3.5")||
   version_in_range(version:offVer, test_version:"14.0", test_version2:"14.3.1")){
  security_message(0);
}
