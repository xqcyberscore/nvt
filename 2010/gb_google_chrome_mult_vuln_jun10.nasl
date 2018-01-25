###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_jun10.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# Google Chrome multiple vulnerabilities - June 10
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow the attackers to cause denial of service.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 5.0.375.55";
tag_insight = "Multiple flaws are due to:
  - An error in canonicalization of URLs, which does not properly follow the
    safe browsing 'specification&qts' requirements for canonicalization of
    'URLs'.
  - A memory error when processing vectors related to the Safe Browsing
    functionality.
  - Unspecified erorrs when processing vectors involving 'unload' event handlers,
    which allow remote attackers to spoof the URL bar.
  - Unspecified errors when processing unknown vectors, which allows remote
    attackers to bypass the 'whitelist-mode' plugin blocker.
  - Unspecified errors when handling the vectors related to the 'drag + drop'
    functionality allows remote attackers to cause a denial of service.
  - It does not properly execute 'JavaScript' code in the extension context,
    which has unspecified impact and remote attack vectors.";
tag_solution = "Upgrade to the Google Chrome 5.0.375.55 or later,
  For updates refer to http://www.google.com/chromeVer";
tag_summary = "The host is running Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800785");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2105", "CVE-2010-2106", "CVE-2010-2107",
                "CVE-2010-2108", "CVE-2010-2109", "CVE-2010-2110");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - June 10");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=41469");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2010/05/stable-channel-update.html");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
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

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 5.0.375.55
if(version_is_less(version:chromeVer, test_version:"5.0.375.55")){
  security_message(0);
}
