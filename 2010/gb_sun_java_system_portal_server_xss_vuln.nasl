###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_system_portal_server_xss_vuln.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# Sun Java System Portal Server Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_solution = "Apply the security patches,
  http://sunsolve.sun.com/search/document.do?assetkey=1-66-269368-1

  *****
  NOTE: Please ignore this warning, if the above mentioned patches are applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "Sun Java System Portal Server Versions 6.3.1, 7.1, and 7.2.";
tag_insight = "The flaws are caused by improper validation of user-supplied input via the
  unspecified parameters to the Gateway component.";
tag_summary = "This host is running Sun Java System Portal Server and is prone to
  multiple unspecified Cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801248");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_cve_id("CVE-2009-4187");
  script_bugtraq_id(37186);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Sun Java System Portal Server Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Dec/1023260.html");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-269368-1");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-138686-04-1");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sun_java_system_portal_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  exit(0);
}

## Get version from KB
ver = get_kb_item("www/" + port + "/Sun/Java/Portal/Server");
if(ver != NULL)
{
  ## Check for vulnerable Sun Java System Portal Server Versions
  if(version_is_equal(version:ver, test_version:"6.3.1") ||
     version_is_equal(version:ver, test_version:"7.1")   ||
     version_is_equal(version:ver, test_version:"7.2")   ){
     security_message(port);
  }
}
