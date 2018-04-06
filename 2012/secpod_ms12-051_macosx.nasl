###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-051_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Office Privilege Elevation Vulnerability - 2721015 (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code
  in the security context of the current user.
  Impact Level: System/Application";
tag_affected = "Microsoft Office 2011 for Mac";
tag_insight = "The application being installed with insecure folder permissions and can
  be exploited to create arbitrary files in certain directories.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-051";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-051.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901210");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1894");
  script_bugtraq_id(54361);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-11 08:54:28 +0530 (Wed, 11 Jul 2012)");
  script_name("Microsoft Office Privilege Elevation Vulnerability - 2721015 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49876/");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-051");

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

## Check for Office Version 2011 (14.2.3)
if(version_in_range(version:offVer, test_version:"14.0", test_version2:"14.2.2")){
  security_message(0);
}
