###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_mar14_lin.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# Google Chrome Multiple Vulnerabilities-01 Mar2014 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:google:chrome";
SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.804330";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6663 $");
  script_cve_id("CVE-2013-6663", "CVE-2013-6664", "CVE-2013-6665", "CVE-2013-6666",
                "CVE-2013-6667", "CVE-2013-6668");
  script_bugtraq_id(65930);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-03-13 11:35:05 +0530 (Thu, 13 Mar 2014)");
  script_name("Google Chrome Multiple Vulnerabilities-01 Mar2014 (Linux)");

  tag_summary =
"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- An use-after-free error within 'SVGImage::setContainerSize' function and
  'FormAssociatedElement::formRemovedFromTree' function in Blink.
- Heap buffer overflow within 'ResourceProvider::InitializeSoftware' function.
- Improper restriction of flash header request within
  'PepperFlashRendererHost::OnNavigate' function.
- Some unspecified errors related to V8 and other few unspecified errors.";

  tag_impact =
"Successful exploitation will allow remote attackers to conduct denial of
service, bypass certain security restrictions, execute arbitrary code and
other unspecified impacts.

Impact Level: System/Application";

  tag_affected =
"Google Chrome version prior to 33.0.1750.146 on Linux.";

  tag_solution =
"Upgrade to version 33.0.1750.146 or later,
For updates refer to http://www.google.com/chrome";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57194");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1029864");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2014/03/stable-channel-update.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
chromeVer = "";

## Get version
if(!chromeVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:chromeVer, test_version:"33.0.1750.146"))
{
  security_message(0);
  exit(0);
}
