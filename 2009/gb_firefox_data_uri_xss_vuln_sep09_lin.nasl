###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_data_uri_xss_vuln_sep09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Firefox 'data:' URI XSS Vulnerability - Sep09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to conduct Cross-Site Scripting
  attacks in the victim's system.
  Impact Level: Application";
tag_affected = "Mozilla, Firefox version 3.0.13 and prior, 3.5 and 3.6/3.7 a1 pre on Linux.";
tag_insight = "Firefox fails to sanitise the 'data:' URIs in Location headers in HTTP
  responses, which can be exploited via vectors related to injecting a Location
  header or Location HTTP response header.";
tag_solution = "Upgrade Firefox version 3.6.3 or later,
  For updates refer to http://www.mozilla.org/";
tag_summary = "This host is installed with Mozilla Product(s) and is prone to
  Cross-Site Scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800890");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3012");
  script_name("Mozilla Firefox 'data:' URI XSS Vulnerability - Sep09 (Linux)");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3323/");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3386/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Linux/Ver");

if(!ffVer)
{
  exit(0);
}

# Grep for Firefox version <= 3.0.13 or 3.5 or 3.6/3.7 a1 pre
if(version_is_less_equal(version:ffVer, test_version:"3.0.13")||
   version_is_equal(version:ffVer, test_version:"3.5")){
  security_message(0);
}
else if(ffVer =~ "^3\.[6|7]a1pre"){
  security_message(0);
}
