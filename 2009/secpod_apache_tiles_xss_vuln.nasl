###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_tiles_xss_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apache Tiles Multiple XSS Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker access the server context
  inside the tiles web application and perform XSS attacks.
  Impact Level: System/Application";
tag_affected = "Apache Tiles version 2.1 to 2.1.1";
tag_insight = "This flaw is due to attribute values or templates are defined using some
  JSP tags 'tiles:putAttribute', 'tiles:insertTemplate' are evaluated twice.";
tag_solution = "Upgrade your Apache Tiles version to 2.1.2
  http://tiles.apache.org/download.html";
tag_summary = "This host has Apache Tiles installed and is prone to Cross-Site
  Script Vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900496");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1275");
  script_bugtraq_id(34657);
  script_name("Apache Tiles Multiple XSS Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_tiles_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "https://issues.apache.org/struts/browse/TILES-351");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc/tiles/framework/trunk/src/site/apt/security/security-bulletin-1.apt?revision=741913");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

tilesPort = get_http_port(default:8080);
if(!tilesPort){
  exit(0);
}

if(!get_port_state(tilesPort)){
  exit(0);
}

version = get_kb_item("www/" + tilesPort + "/Apache/Tiles");
version = eregmatch(pattern:"^(.+) under (/.*)$", string:version);
if(version[1] == NULL){
  exit(0);
}

if(version_in_range(version:version[1], test_version:"2.1",
                    test_version2:"2.1.1")){
  security_message(tilesPort);
}
