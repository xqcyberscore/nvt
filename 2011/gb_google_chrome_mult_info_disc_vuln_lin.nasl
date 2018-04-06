###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_info_disc_vuln_lin.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Google Chrome Multiple Information Disclosure Vulnerabilities (Linux)
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

tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information about visited web pages by calling getComputedStyle method or
  via a crafted HTML document.
  Impact Level: Application";
tag_affected = "Google Chrome version 4.x on Linux.";
tag_insight = "Multiple vulnerabilities are due to implementation erros in,
  - The JavaScript failing to restrict the set of values contained in the
    object returned by the getComputedStyle method.
  - The Cascading Style Sheets (CSS) failing to handle the visited pseudo-class.";
tag_solution = "Upgrade to the Google Chrome version 5.0 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to multiple
  information disclosure vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802357");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2010-5073", "CVE-2010-5069");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-09 12:15:25 +0530 (Fri, 09 Dec 2011)");
  script_name("Google Chrome Multiple Information Disclosure Vulnerabilities (Linux)");
  script_xref(name : "URL" , value : "http://w2spconf.com/2010/papers/p26.pdf");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Versions 4.x
if(version_in_range(version:chromeVer, test_version:"4.0", test_version2:"4.2")){
  security_message(0);
}
