###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_server_mult_unspecified_vuln.nasl 3047 2016-04-11 13:58:34Z benallard $
#
# Oracle GlassFish Server Multiple Unspecified Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_solution = "Apply the security updates.
  http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation will allow attackers to affect confidentiality,
  integrity and availability via unknown vectors.
  Impact Level: Application";
tag_affected = "Oracle GlassFish Server version 2.1.1, 3.1.1 and 3.0.1";
tag_insight = "Multiple unspecified flaws are exists in the application related to
  Administration and Web Container, which allows attackers to affect
  confidentiality, integrity and availability via unknown vectors.";
tag_summary = "The host is running GlassFish Server and is prone to multiple
  unspecified vulnerabilities.";

if(description)
{
  script_id(802417);
  script_version("$Revision: 3047 $");
  script_cve_id("CVE-2012-0081", "CVE-2011-3564", "CVE-2012-0104");
  script_bugtraq_id(51484, 51485, 51497);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-04-11 15:58:34 +0200 (Mon, 11 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-01-23 13:43:23 +0530 (Mon, 23 Jan 2012)");
  script_name("Oracle GlassFish Server Multiple Unspecified Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/47603/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026537");
  script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0081");
  script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3564");
  script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0104");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujan2012-366304.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check for the version of Oracle GlassFish Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("GlassFish_detect.nasl");
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

## Check for the default port
if(!port = get_http_port(default:8080)){
  port = 8080;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Get the version form KB
vers = get_kb_item(string("www/", port, "/GlassFish"));
if(isnull(vers)){
  exit(0);
}

if(version_is_equal(version: vers, test_version:"2.1.1") ||
   version_is_equal(version: vers, test_version:"3.0.1") ||
   version_is_equal(version: vers, test_version:"3.1.1")){
  security_message(port:port);
}
