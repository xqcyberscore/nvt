###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_unspecified_vuln_oct10_win.nasl 8258 2017-12-29 07:28:57Z teissa $
#
# Mozilla Firefox Unspecified Vulnerability Oct-10 (Windows)
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
code via unknown vectors.

Impact Level: System/Application";

tag_affected = "Mozilla Firefox version 3.5.x through 3.5.14
Mozilla Firefox version 3.6.x through 3.6.11";

tag_insight = "The flaw is due to unspecified vulnerability, when JavaScript is
enabled.";

tag_solution = "Upgrade to Mozilla Firefox version 3.5.15 or 3.6.12.
For updates refer to http://www.mozilla.com/en-US/firefox/upgrade.html";

tag_summary = "The host is installed with Mozilla Firefox and is prone to
unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801475");
  script_version("$Revision: 8258 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_cve_id("CVE-2010-3765");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Unspecified Vulnerability Oct-10 (Windows)");
  script_xref(name : "URL" , value : "http://isc.sans.edu/diary.html?storyid=9817");
  script_xref(name : "URL" , value : "http://www.norman.com/about_norman/press_center/news_archive/2010/129223/");
  script_xref(name : "URL" , value : "http://blog.mozilla.com/security/2010/10/26/critical-vulnerability-in-firefox-3-5-and-firefox-3-6/");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
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

## Get Firefox version from KB
fpVer = get_kb_item("Firefox/Win/Ver");
if(!fpVer){
  exit(0);
}

## Check for Mozilla Firefox Version  3.5 to 3.5.14 and 3.6 to 3.6.11
if(version_in_range(version:fpVer, test_version:"3.5.0", test_version2:"3.5.14")||
   version_in_range(version:fpVer, test_version:"3.6.0", test_version2:"3.6.11")){
  security_message(0);
}
