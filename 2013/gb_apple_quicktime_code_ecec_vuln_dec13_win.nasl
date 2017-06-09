###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_code_ecec_vuln_dec13_win.nasl 34122 2013-12-31 12:44:42Z dec$
#
# Apple QuickTime Pictureviewer Arbitrary Code Execution Vulnerability Dec13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:quicktime";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804053";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6093 $");
  script_cve_id("CVE-2010-1819");
  script_bugtraq_id(42774);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2013-12-31 12:44:42 +0530 (Tue, 31 Dec 2013)");
  script_name("Apple QuickTime Pictureviewer Arbitrary Code Execution Vulnerability Dec13 (Windows)");

  tag_summary =
"This host is installed with Apple QuickTime and is prone to code execution
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to the PictureViewer application loading libraries
(e.g. CoreGraphics.dll) in an insecure manner.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code and
compromise a vulnerable system.

Impact Level: System/Application";

  tag_affected =
"Apple QuickTime version before 7.6.8 on Windows";

  tag_solution =
"Upgrade to Apple QuickTime version 7.6.8 or later,
For updates refer to http://support.apple.com/downloads";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4339");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41123");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2010/Sep/msg00003.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
quickVer = "";

## Get version
if(!quickVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check for QuickTime Player Version less than 7.6.8 (7.68.75.0)
if(version_is_less(version:quickVer, test_version:"7.68.75.0"))
{
  security_message(0);
  exit(0);
}
