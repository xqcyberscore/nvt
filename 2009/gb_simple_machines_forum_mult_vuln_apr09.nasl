###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_machines_forum_mult_vuln_apr09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Simple Machines Forum Multiple Vulnerabilities.
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Successful exploitation will let the attacker execute malicious arbitrary
  codes in the context of the SMF web application to gain administrative
  privileges, install malicious components into the forum context or can
  cause directory traversal attacks also.
  Impact Level: Application.";
tag_affected = "Simple Machines Forum version 1.0 to 1.0.14
  Simple Machines Forum version 1.1 to 1.1.6";
tag_insight = "Multiple flaws are due to
  - Lack of access control and validation check while performing certain
    HTTP requests which lets the attacker perform certain administrative
    commands.
  - Lack of validation check for the 'theme_dir' settings before being
    used which causes arbitrary code execution from local resources.
  - Crafted avatars are being allowed for code execution.";
tag_solution = "Update your Simple Machines Forum version to 1.1.7 or later
  http://www.simplemachines.org";
tag_summary = "This host has Simple Machines Forum installed which is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800558");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6657", "CVE-2008-6658", "CVE-2008-6659");
  script_bugtraq_id(32119, 32139);
  script_name("Simple Machines Forum Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32516");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6993");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7011");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46343");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");
include("http_func.inc");

httpPort = get_http_port(default:80);
if(!httpPort){
  httpPort = 80;
}

if(!get_port_state(httpPort)){
  exit(0);
}

ver = get_kb_item("www/" + httpPort + "/SMF");
ver = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);
if(ver[1] == NULL){
  exit(0);
}

if((version_in_range(version:ver[1], test_version:"1.0", test_version2:"1.0.14"))||
   (version_in_range(version:ver[1], test_version:"1.1", test_version2:"1.1.6"))){
 security_message(httpPort);
}
