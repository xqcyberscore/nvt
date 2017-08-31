###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_aug14_macosx.nasl 6735 2017-07-17 09:56:49Z teissa $
#
# Google Chrome Multiple Vulnerabilities - 01 Aug14 (Mac OS X)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804811");
  script_version("$Revision: 6735 $");
  script_cve_id("CVE-2014-3165", "CVE-2014-3166", "CVE-2014-3167");
  script_bugtraq_id(69201, 69202, 69203);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-08-19 11:25:08 +0530 (Tue, 19 Aug 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 Aug14 (Mac OS X)");

    tag_summary =
"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to
- Use-after-free vulnerability in websockets/WorkerThreadableWebSocketChannel.cpp
script within the Web Sockets implementation in Blink.
- An error within SPDY and other multiple unspecified errors.";

  tag_impact =
"Successful exploitation will allow remote attackers to disclose potentially
sensitive information, conduct a denial of service attack and potentially
execute arbitrary code or possibly have other impact via unknown vectors.

Impact Level: System/Application";

  tag_affected =
"Google Chrome version prior to 36.0.1985.143 on Mac OS X.";

  tag_solution =
"Upgrade to Google Chrome 36.0.1985.143 or later,
For updates refer to http://www.google.com/chrome";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/59904");
  script_xref(name : "URL" , value : "https://www.hkcert.org/my_url/en/alert/14081401");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2014/08/stable-channel-update.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
chromeVer = "";

## Get version
if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:chromeVer, test_version:"36.0.1985.143"))
{
  security_message(0);
  exit(0);
}
