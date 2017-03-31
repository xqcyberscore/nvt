###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_sep11_win.nasl 3103 2016-04-18 14:50:34Z benallard $
#
# Google Chrome multiple vulnerabilities - September11 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions, or cause a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 13.0.782.215 on Windows.";
tag_insight = "Multiple flaws are due to,
  - URL parsing error when located on the command line.
  - Multiple use-after-free error exists within the handling of features like
    line boxes, counter nodes, custom fonts and text searching.
  - A double free error exists in libxml when handling XPath expression.
  - Memory corruption error when handling certain vertex data.
  - An error related to empty origins allows attackers to violate the
    cross-origin policy.
  - An integer overflow error in uniform arrays.";
tag_solution = "Upgrade to the Google Chrome 13.0.782.215 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802326);
  script_version("$Revision: 3103 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-18 16:50:34 +0200 (Mon, 18 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_cve_id("CVE-2011-2822", "CVE-2011-2823", "CVE-2011-2824", "CVE-2011-2825",
                "CVE-2011-2821", "CVE-2011-2826", "CVE-2011-2806", "CVE-2011-2827",
                "CVE-2011-2828", "CVE-2011-2829");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - September11 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45698/");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/08/stable-channel-update_22.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

## Check for Google Chrome Version less than 13.0.782.215
if(version_is_less(version:chromeVer, test_version:"13.0.782.215")){
  security_message(0);
}
