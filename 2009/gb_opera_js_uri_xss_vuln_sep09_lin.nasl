###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_js_uri_xss_vuln_sep09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Opera 'javascript: URI' XSS Vulnerability - Sep0 (Linux)
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
tag_affected = "Opera version 9.52 and prior and 10.00 Beta 3 Build 1699 on Linux.";
tag_insight = "Error occurs when application fails to sanitise the 'javascript:' and 'data:'
  URIs in Location headers in HTTP responses, which can be exploited via vectors
  related to injecting a Location header.";
tag_solution = "Upgrade to Opera version 9.64 or later and 10.10 or later.
  For updates refer to http://www.opera.com/";
tag_summary = "This host is installed with Opera Web Browser and is prone to
  Cross-Site Scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800882");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3013");
  script_name("Opera 'javascript: URI' XSS Vulnerability - Sep09 (Linux)");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3386/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_require_keys("Opera/Build/Linux/Ver");
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

operaVer = get_kb_item("Opera/Build/Linux/Ver");
if(isnull(operaVer))
{
  exit(0);
}

# Check for Opera Version <= 9.52 (9.52.2091)
#                    and 10.00 Beta 3 Build 1699 (10.00.1699)
if(version_is_less_equal(version:operaVer, test_version:"9.52.2091")||
   version_is_equal(version:operaVer, test_version:"10.00.1699")){
  security_message(0);
}
