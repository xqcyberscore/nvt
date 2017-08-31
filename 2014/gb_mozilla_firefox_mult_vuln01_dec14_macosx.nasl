###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln01_dec14_macosx.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Mozilla Firefox Multiple Vulnerabilities-01 Dec14 (Mac OS X)
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805217");
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2014-1595", "CVE-2014-1594", "CVE-2014-1593", "CVE-2014-1592",
                "CVE-2014-1590", "CVE-2014-1589", "CVE-2014-1588", "CVE-2014-1587",
                "CVE-2014-8632", "CVE-2014-8631");
  script_bugtraq_id(71394, 71396, 71395, 71398, 71397, 71393, 71392, 71391, 71556,
                    71560);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-12-16 09:44:04 +0530 (Tue, 16 Dec 2014)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-01 Dec14 (Mac OS X)");

  script_tag(name: "summary" , value:"This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exist due to,
  - The CoreGraphics framework logging potentially sensitive input data
  to the /tmp directory.
  - A bad cast issue from the BasicThebesLayer to BasicContainerLayer.
  - An error when parsing media content within the 'mozilla::FileBlockCache::Read'
  function.
  - A use-after-free error when parsing certain HTML within the
  'nsHtml5TreeOperation' class.
  - An error that is triggered when handling JavaScript objects that are passed
  to XMLHttpRequest that mimics an input stream.
  - An error that is triggered when handling a CSS stylesheet that has its namespace
  improperly declared.
  - Multiple unspecified errors.
  - An error when filtering object properties via XrayWrappers.
  - An error when passing Chrome Object Wrappers (COW) protected chrome objects as
  native interfaces.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information, compromise a user's system, bypass
  certain security restrictions and other unknown impacts.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Mozilla Firefox before version 34.0 on Mac OS X");

  script_tag(name: "solution" , value:"Upgrade to Mozilla Firefox version 34.0
  or later, For updates refer to http://www.mozilla.com/en-US/firefox/all.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60558");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-83");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-84");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ffVer = "";

## Get version
if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

# Check for vulnerable version
if(version_is_less(version:ffVer, test_version:"34.0"))
{
  security_message(0);
  exit(0);
}
