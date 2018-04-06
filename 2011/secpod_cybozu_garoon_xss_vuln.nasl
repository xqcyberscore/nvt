###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cybozu_garoon_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Cybozu Garoon Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to to execute arbitrary
  HTML and script code in a user's browser session in context of an affected
  site.
  Impact Level: Application";
tag_affected = "Cybozu Garoon version 2.0.0 through 2.1.3";
tag_insight = "The flaw is caused by improper validation of unspecified user-supplied input,
  which allows attackers to execute arbitrary HTML and script code in a user's
  browser session in context of an affected site.";
tag_solution = "Upgrade to Cybozu Garoon version 2.5.0 or later.
  For updates refer to http://products.cybozu.co.jp/garoon/download/";
tag_summary = "This host is running Cybozu Garoon and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902534");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-1332");
  script_bugtraq_id(48446);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Cybozu Garoon Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN59779256/index.html");
  script_xref(name : "URL" , value : "http://cybozu.co.jp/products/dl/notice/detail/0023.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000044.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Check for Cybozu Garoon version 2.0.0 through 2.1.3
if(vers = get_version_from_kb(port:port,app:"CybozuGaroon"))
{
  if(version_in_range(version:vers, test_version:"2.0.0", test_version2:"2.1.3")){
    security_message(port:port);
  }
}
