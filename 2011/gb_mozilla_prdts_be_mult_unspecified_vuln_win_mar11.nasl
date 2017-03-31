###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_be_mult_unspecified_vuln_win_mar11.nasl 3112 2016-04-19 08:52:10Z antu123 $
#
# Mozilla Products Browser Engine Multiple Unspecified Vulnerabilities March-11 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_solution = "Upgrade to Firefox version 3.6.14 or later
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Thunderbird version 3.1.8 or later
  http://www.mozillamessaging.com/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code via unknown vectors.
  Impact Level: Application";
tag_affected = "Thunderbird 3.1.x before 3.1.8
  Firefox version before 3.6.x before 3.6.14";
tag_insight = "Multiple unspecified vulnerabilities are present in the browser engine,
  which allow remote attackers to cause a denial of service.";
tag_summary = "The host is installed with Mozilla Firefox/Thunderbird that are prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801905);
  script_version("$Revision: 3112 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 10:52:10 +0200 (Tue, 19 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-0062");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Browser Engine Multiple Unspecified Vulnerabilities March-11 (Windows)");

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0531");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-09.html");

  script_tag(name:"qod_type", value:"registry");
  script_summary("Check for the version of Mozilla Firefox/Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl","gb_thunderbird_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver", "Thunderbird/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

## Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  ## Grep for Firefox version 3.6.x < 3.6.14
  if(version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.13"))
  {
    security_message(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version < 3.1.8
  if(version_in_range(version:tbVer, test_version:"3.1.0", test_version2:"3.1.7")){
    security_message(0);
  }
}
