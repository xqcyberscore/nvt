###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_apr14_macosx.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Google Chrome Multiple Vulnerabilities - 01 Apr14 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.804549";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2014-1716", "CVE-2014-1717", "CVE-2014-1718", "CVE-2014-1719",
                "CVE-2014-1720", "CVE-2014-1721", "CVE-2014-1722", "CVE-2014-1723",
                "CVE-2014-1724", "CVE-2014-1725", "CVE-2014-1726", "CVE-2014-1727",
                "CVE-2014-1728", "CVE-2014-1729");
  script_bugtraq_id(66704);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-22 13:36:13 +0530 (Tue, 22 Apr 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 Apr14 (Mac OS X)");

  tag_summary =
"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- A use-after-free error exists within 'web workers', 'DOM', 'forms' and 'speech'.
- An unspecified error exists when handling URLs containing 'RTL' characters.
- An integer overflow error exists within 'compositor'.
- An error when handling certain 'window property'.
- An unspecified error within 'V8'.";

 tag_impact =
"Successful exploitation will allow remote attackers to conduct cross-site
scripting attacks, bypass certain security restrictions, and compromise
a user's system.

Impact Level: System/Application";

  tag_affected =
"Google Chrome version prior to 34.0.1847.116 on Mac OS X.";

  tag_solution =
"Upgrade to Google Chrome 34.0.1847.116 or later,
For updates refer to http://www.google.com/chrome";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57506");
  script_xref(name : "URL" , value : "http://threatpost.com/google-patches-31-flaws-in-chrome/105326");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2014/04/stable-channel-update.html");
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
if(!chromeVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:chromeVer, test_version:"34.0.1847.116"))
{
  security_message(0);
  exit(0);
}
