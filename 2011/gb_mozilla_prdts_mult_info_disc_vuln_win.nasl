###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_info_disc_vuln_win.nasl 3100 2016-04-18 14:41:20Z benallard $
#
# Mozilla Products Multiple Information Disclosure Vulnerabilities - (Windows)
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

tag_solution = "Upgrade to Mozilla Firefox version 4.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.1 or later
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version 3.3 or later
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to obtain sensitive information
  about visited web pages.
  Impact Level: Application";
tag_affected = "SeaMonkey version prior to 2.1,
  Thunderbird version prior to 3.3 and
  Mozilla Firefox version prior to 4.0 on Windows";
tag_insight = "The flaws are due to
  - An error in layout engine, executes different code for visited and
    unvisited links during the processing of CSS token sequences.
  - An error in JavaScript implementation, which does not properly restrict
    the set of values of objects returned by the getComputedStyle method.
  - An error in Cascading Style Sheets (CSS) implementation, which fails to
    handle the visited pseudo-class.";
tag_summary = "The host is installed with Mozilla firefox/seamonkey/thunderbird
  and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(802545);
  script_version("$Revision: 3100 $");
  script_cve_id("CVE-2010-5074", "CVE-2002-2437", "CVE-2002-2436");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-04-18 16:41:20 +0200 (Mon, 18 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-12-09 14:17:09 +0530 (Fri, 09 Dec 2011)");
  script_name("Mozilla Products Multiple Information Disclosure Vulnerabilities - (Windows)");

  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2010-5074");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2002-2436");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2002-2437");
  script_xref(name : "URL" , value : "http://vrda.jpcert.or.jp/feed/en/NISTNVD_CVE-2010-5074_AD_1.html");

  script_summary("Check for the version of Mozilla Firefox/SeaMonkey/Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver", "Seamonkey/Win/Ver",
                      "Thunderbird/Win/Ver");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"4.0"))
  {
     security_message(0);
     exit(0);
  }
}

# SeaMonkey Check
seaVer = get_kb_item("Seamonkey/Win/Ver");
if(seaVer)
{
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.1"))
  {
    security_message(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  # Grep for Thunderbird version <= 3.3
  if(version_is_less(version:tbVer, test_version:"3.3")){
    security_message(0);
  }
}
