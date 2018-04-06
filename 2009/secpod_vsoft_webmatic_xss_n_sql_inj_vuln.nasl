###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vsoft_webmatic_xss_n_sql_inj_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Valarsoft Webmatic Multiple XSS and SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker cause Cross-Site Scripting or
  SQL Injection attacks by executing arbitrary codes within the context of the
  affected application.
  Impact Level: Application.";
tag_affected = "Valarsoft Webmatic prior to 3.0.3";
tag_insight = "- Certain unspecified input is not properly sanitised before being returned to
    the user. This can be exploited to execute arbitrary HTML and script code in
    a user's browser session in the context of an affected site.
  - Certain unspecified input is not properly sanitised before being used in SQL
    queries. This can be exploited to manipulate SQL queries by injecting
    arbitrary SQL code.";
tag_solution = "Upgrade to Valarsoft Webmatic version 3.0.3.
  For updates refer to http://www.valarsoft.com";
tag_summary = "This host is running Valarsoft Webmatic and is prone to multiple
  Cross-Site Scripting and SQL Injection vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901088");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-12-24 14:01:59 +0100 (Thu, 24 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4379", "CVE-2009-4380");
  script_bugtraq_id(37335);
  script_name("Valarsoft Webmatic Multiple XSS and SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37735");
  script_xref(name : "URL" , value : "http://www.valarsoft.com/index.php?stage=0&section=5&newsID=165&action=6");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_valarsoft_webmatic_detect.nasl");
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

webmaticPort = get_http_port(default:80);
if(!webmaticPort){
  exit(0);
}

webmaticVer = get_kb_item("www/"+ webmaticPort + "/Valarsoft/Webmatic");
if(!webmaticVer){
  exit(0);
}

webmaticVer = eregmatch(pattern:"^(.+) under (/.*)$", string:webmaticVer);
if(webmaticVer[1])
{
  # Check for Volarsoft Webmatic prior to 3.0.3
  if(version_is_less(version:webmaticVer[1], test_version:"3.0.3")){
    security_message(webmaticPort);
  }
}
