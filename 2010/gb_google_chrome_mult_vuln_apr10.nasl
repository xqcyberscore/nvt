###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_apr10.nasl 8187 2017-12-20 07:30:09Z teissa $
#
# Google Chrome Multiple Vulnerabilities (win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary code, bypass
  security restrictions, sensitive information disclosure, and can cause other
  attacks.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 4.1.249.1036 on Windows.";
tag_insight = "Multiple flaws are due to:
  - An error in handling 'SVG' document.
  - Multiple race conditions in the 'sandbox' infrastructure.
  - An error in 'sandbox' infrastructure which does not properly use pointers.
  - An error in proceesing of 'HTTP' headers, processes HTTP headers before
    invoking the SafeBrowsing feature.
  - not having the expected behavior for attempts to delete Web SQL
    Databases and clear the 'Strict Transport Security (STS)' state.
  - An error in processing of 'HTTP Basic Authentication dialog'.
  - Multiple integer overflows errors when processing 'WebKit JavaScript'
    objects.
  - not properly restricting cross-origin operations, which has unspecified
    impact and remote attack vectors.";
tag_solution = "Upgrade to the version 4.1.249.1036 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome Web Browser and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801312");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-1228", "CVE-2010-1229", "CVE-2010-1230", "CVE-2010-1231",
                "CVE-2010-1232", "CVE-2010-1233", "CVE-2010-1234", "CVE-2010-1235",
                "CVE-2010-1236",  "CVE-2010-1237");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome Multiple Vulnerabilities (win)");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=37061");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2010/03/stable-channel-update.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

gcVer = get_kb_item("GoogleChrome/Win/Ver");
if(!gcVer){
  exit(0);
}

# Check for google chrome Version less than 4.1.249.1036
if(version_is_less(version:gcVer, test_version:"4.1.249.1036")){
  security_message(0);
}
