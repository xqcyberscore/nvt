###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_itunes_tutorials_sec_bypass_win.nasl 8169 2017-12-19 08:42:31Z cfischer $
#
# Apple iTunes Tutorials Window Security Bypass Vulnerability (Windows)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod
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

CPE = "cpe:/a:apple:itunes";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804232";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8169 $");
  script_cve_id("CVE-2014-1242");
  script_bugtraq_id(65088);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 09:42:31 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-01-30 16:54:49 +0530 (Thu, 30 Jan 2014)");
  script_name("Apple iTunes Tutorials Window Security Bypass Vulnerability (Windows)");

  tag_summary =
"This host is installed with Apple iTunes and is prone to security bypass
vulnerability.";

  tag_vuldetect =
"Get the installed version of Apple iTunes and check the version is vulnerable
or not.";

  tag_insight =
"The flaw exists due to iTunes Tutorials window, which uses a non-secure HTTP
connection to retrieve content.";

  tag_impact =
"Successful exploitation may allow an attacker to perform man-in-the-middle
attacks and obtain sensitive information..

Impact Level: Application.";

  tag_affected =
"Apple iTunes before 11.1.4 on Windows";

  tag_solution =
"Upgrade to version 11.1.4 or later,
For updates refer to http://www.apple.com/itunes/download";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/90653");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT6001");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ituneVer = "";

## Get version
if(!ituneVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
    exit(0);
}

## Check for the vulnerable version
if(version_is_less(version:ituneVer, test_version:"11.1.4"))
{
  security_message(0);
  exit(0);
}
