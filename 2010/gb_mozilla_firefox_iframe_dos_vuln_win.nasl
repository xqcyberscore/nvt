###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_iframe_dos_vuln_win.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# Mozilla Firefox 'IFRAME' Denial Of Service vulnerability (Windows)
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

tag_impact = "Successful exploitation will allow remote attackers to cause a
denial of service.

Impact Level: Application";

tag_affected = "Firefox version 3.0.x prior to 3.0.19, 3.5.x prior to 3.5.9,
3.6.x prior to 3.6.3";

tag_insight = "The flaw is due to improper handling of 'JavaScript' code which
contains an infinite loop, that creates IFRAME elements for invalid news://
or nntp:// URIs.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed with Mozilla Firefox browser and is prone
to Denial of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801347");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2117");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Mozilla Firefox 'IFRAME' Denial Of Service vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/4238/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511509/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version <= 3.0.19, <= 3.5.9, <= 3.6.2
  if(version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.9") ||
     version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.19") ||
     version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.3")) {
      security_message(0);
  }
}
