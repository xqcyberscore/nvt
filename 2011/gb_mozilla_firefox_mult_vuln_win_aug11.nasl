###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln_win_aug11.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Mozilla Firefox Multiple Vulnerabilities August-11 (Windows)
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

tag_impact = "Successful exploitation allows remote attackers to overwrite or delete
  arbitrary cookies via a Set-Cookie header in an HTTP response, which results
  into cross site scripting, cross site request forgery and denial of service
  attacks.
  Impact Level: Application";
tag_affected = "Mozilla Firefox versions before 4.0";
tag_insight = "Multiple flaws are due to not properly restricting modifications to
  cookies established in HTTPS sessions.";
tag_solution = "Upgrade to Firefox version 4.0 or later
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802138);
  script_version("$Revision: 5351 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_cve_id("CVE-2008-7293");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Mozilla Firefox Multiple Vulnerabilities August-11 (Windows)");
  script_xref(name : "URL" , value : "http://scarybeastsecurity.blogspot.com/2008/11/cookie-forcing.html");
  script_xref(name : "URL" , value : "http://scarybeastsecurity.blogspot.com/2011/02/some-less-obvious-benefits-of-hsts.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_summary("Check for the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  ## Grep for Firefox versions before 4.0
  if(version_is_less(version:ffVer, test_version:"4.0")){
    security_message(0);
  }
}
