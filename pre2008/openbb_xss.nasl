# OpenVAS Vulnerability Test
# $Id: openbb_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: OpenBB XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote host seems to be running OpenBB, a forum management system written
in PHP.

The remote version of this software is vulnerable to cross-site scripting 
attacks, through the script 'board.php'.

Using a specially crafted URL, an attacker can cause arbitrary code execution 
for third party users, thus resulting in a loss of integrity of their system.";

tag_solution = "Upgrade to the latest version of this software.";

#  Ref: gr00vy <groovy2600@yahoo.com.ar>

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.14822");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(9303);
 script_xref(name:"OSVDB", value:"3220");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("OpenBB XSS");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_active");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

foreach dir( make_list_unique( "/openbb", cgi_dirs( port:port ) ) ) {

 if( dir == "/" ) dir = "";
 req = http_get(item:string(dir, "/board.php?FID=%3Cscript%3Efoo%3C/script%3E"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) continue;
 if(res =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:res)) {
   security_message(port);
   exit(0);
 }
}

exit( 99 );