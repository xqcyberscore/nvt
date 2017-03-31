###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_code_exec_vuln_nov12_win.nasl 3565 2016-06-21 07:20:17Z benallard $
#
# Mozilla Firefox Code Execution Vulnerabilities - November12 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to gain privileges or execute
  arbitrary code in the context of the browser.
  Impact Level: System/Application";
tag_affected = "Mozilla Firefox version before 17.0 on Windows";
tag_insight = "- Improper loading of DLL file in the default downloads directory by Firefox
    installer.
  - An error within Style Inspector when parsing style sheets can be exploited
    to execute HTML and CSS code in chrome privileged context.";
tag_solution = "Upgrade to Mozilla Firefox version 17.0 later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "This host is installed with Mozilla Firefox and is prone to multiple
  code execution vulnerabilities.";

if(description)
{
  script_id(803061);
  script_version("$Revision: 3565 $");
  script_cve_id("CVE-2012-4206", "CVE-2012-4210");
  script_bugtraq_id(56625, 56646);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:20:17 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-11-26 14:52:10 +0530 (Mon, 26 Nov 2012)");
  script_name("Mozilla Firefox Code Execution Vulnerabilities - November12 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51358");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027791");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027792");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-98.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-104.html");

  script_summary("Check for the vulnerable version of Mozilla Firefox on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
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

# Variable Initialization
ffVer = "";

# Get FireFox version
ffVer = get_kb_item("Firefox/Win/Ver");

if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"17.0"))
  {
    security_message(0);
    exit(0);
  }
}
