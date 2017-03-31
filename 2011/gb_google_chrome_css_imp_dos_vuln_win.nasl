###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_css_imp_dos_vuln_win.nasl 3103 2016-04-18 14:50:34Z benallard $
#
# Google Chrome 'WebKit' CSS Implementation DoS Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow the attackers to cause denial-of-service
  via crafted JavaScript code.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 11.0.696.43";
tag_insight = "The flaw is due to error in 'counterToCSSValue()' function in
  'CSSComputedStyleDeclaration.cpp' in the Cascading Style Sheets (CSS)
  implementation in WebCore in WebKit, it does not properly handle access to
  the 'counterIncrement', 'counterReset' attributes of CSSStyleDeclaration data
  provided by a getComputedStyle method call.";
tag_solution = "Upgrade to the Google Chrome 11.0.696.43 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed Google Chrome and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(801773);
  script_version("$Revision: 3103 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-18 16:50:34 +0200 (Mon, 18 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1691");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Google Chrome 'WebKit' CSS Implementation DoS Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=77665");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/04/beta-channel-update_12.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 11.0.696.43
if(version_is_less(version:chromeVer, test_version:"11.0.696.43")){
  security_message(0);
}
