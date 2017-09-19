###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_info_disclosure_vuln_dec13_macosx.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Apple Safari Information Disclosure Vulnerability Dec13 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804175";
CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2013-7127");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2013-12-19 20:34:20 +0530 (Thu, 19 Dec 2013)");
  script_name("Apple Safari Information Disclosure Vulnerability Dec13 (Mac OS X)");

  tag_summary =
"This host is installed with Apple Safari and is prone to information
disclosure vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw exists in the 'Reopen All Windows from Last Session' feature that
stores user ID and password information in the LastSession.plist file";

  tag_impact =
"Successful exploitation will allow local users to obtain sensitive
information.

Impact Level: Application";

  tag_affected =
"Apple Safari version 6.0.5 on Mac OS X";

  tag_solution =
"Upgrade to Apple Safari version 6.1 or later,
For updates refer to 'http://www.apple.com/support'";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.securelist.com/en/blog/8168/Loophole_in_Safari");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

# Variable Initialization
safVer = "";

## Get Apple Safari version
if(!safVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check for Apple Safari Versions less than 6.0.5
if(version_is_equal(version:safVer, test_version:"6.0.5"))
{
  security_message(0);
  exit(0);
}
