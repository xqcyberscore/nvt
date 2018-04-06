###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_oct12_lin.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-01 Oct12 (Linux)
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
  with the privileges of a local user and cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 22.0.1229.92 on Linux";
tag_insight = "Multiple flaws are due to
  - A race condition error exists related to audio device handling.
  - An error exists related to Skia text rendering, ICU regex, compositor
    handling and plug-in crash monitoring for Pepper plug-ins.";
tag_solution = "Upgrade to the Google Chrome 22.0.1229.92 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802471");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-2900", "CVE-2012-5108", "CVE-2012-5109", "CVE-2012-5110",
                "CVE-2012-5111");
  script_bugtraq_id(55830);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-10-15 12:21:19 +0530 (Mon, 15 Oct 2012)");
  script_name("Google Chrome Multiple Vulnerabilities-01 Oct12 (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50872/");
  script_xref(name : "URL" , value : "https://www.securelist.com/en/advisories/50872");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/10/stable-channel-update.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_require_keys("Google-Chrome/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 22.0.1229.92
if(version_is_less(version:chromeVer, test_version:"22.0.1229.92")){
  security_message(0);
}
