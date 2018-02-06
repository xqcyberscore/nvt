###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_sep12_macosx.nasl 8671 2018-02-05 16:38:48Z teissa $
#
# Google Chrome Multiple Vulnerabilities - Sep12 (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow the attackers to execute arbitrary code
  or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 21.0.1180.89 on Mac OS X";
tag_insight = "Multiple flaws are due to
  - Out-of-bounds read in line breaking
  - Bad cast with run-ins.
  - Browser crash with SPDY.
  - Race condition with workers and XHR.
  - Avoid stale buffer in URL loading.
  - Lower severity memory management issues in XPath
  - Bad cast in XSL transforms.
  - XSS in SSL interstitial.";
tag_solution = "Upgrade to the Google Chrome 21.0.1180.89 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802449");
  script_version("$Revision: 8671 $");
  script_cve_id("CVE-2012-2869", "CVE-2012-2868", "CVE-2012-2867", "CVE-2012-2866",
                "CVE-2012-2865", "CVE-2012-2872", "CVE-2012-2871", "CVE-2012-2870");
  script_bugtraq_id(55331);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-09-03 16:01:42 +0530 (Mon, 03 Sep 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - Sep12 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50447");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55331");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/08/stable-channel-update_30.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_require_keys("GoogleChrome/MacOSX/Version");
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
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Versions prior to 21.0.1180.89
if(version_is_less(version:chromeVer, test_version:"21.0.1180.89")){
  security_message(0);
}
