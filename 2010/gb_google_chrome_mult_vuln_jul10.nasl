###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_jul10.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# Google Chrome multiple vulnerabilities - July 10
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
tag_affected = "Google Chrome version prior to 5.0.375.99";
tag_insight = "Multiple flaws are due to:
  - out-of-bounds read error with 'WebGL'.
  - Application fails to isolate 'isandboxed IFRAME' elements, which has
    unspecified impact and remote attack vectors.
  - Memory corruption error in 'Unicode Bidirectional' Algorithm.
  - Invalid 'SVG' document, which allows remote attackers to cause a denial
    of service.
  - Unspecified error, which allows remote attackers to cause a denial of
    service via an invalid image.
  - Memory corruption with invalid 'PNG', 'CSS style rendering'.
  - Unspecified error in 'annoyance with print dialogs'.
  - Application fails to properly implement 'modal dialogs'.";
tag_solution = "Upgrade to the Google Chrome 5.0.375.99 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800800");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)");
  script_cve_id("CVE-2010-2645", "CVE-2010-2646", "CVE-2010-2648",
                "CVE-2010-2647", "CVE-2010-2649", "CVE-2010-2651",
                "CVE-2010-2650", "CVE-2010-2652");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - July 10");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2010/07/stable-channel-update.html");

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

## Check for Google Chrome Version less than 5.0.375.99
if(version_is_less(version:chromeVer, test_version:"5.0.375.99")){
  security_message(0);
}
