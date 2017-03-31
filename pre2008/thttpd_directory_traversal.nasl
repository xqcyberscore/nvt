# OpenVAS Vulnerability Test
# $Id: thttpd_directory_traversal.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: HTTP Directory Traversal (Windows)
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

tag_summary = "The remote web server is vulnerable to a path traversal vulnerability.

An attacker may exploit this flaw to read arbitrary files on the remote
system with the privileges of the http process.";

tag_solution = "upgrade your web server or change it.";

if(description)
{
 script_id(14229);
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2628");
 script_bugtraq_id(10862);
 script_xref(name:"OSVDB", value:"8372");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 
 name = "HTTP Directory Traversal (Windows)";
 script_name(name);
 


 summary = "thttpd flaw in 2.0.7 windows port";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Remote file access";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"c:\boot.ini", port:port);
  send(socket:soc, data:buf);
  rep = http_recv(socket:soc);
  if ( '\r\n\r\n' >< rep )
   rep = strstr(rep, '\r\n\r\n');

  if(egrep(pattern:"\[boot loader\]", string:rep))
  {
    txt  = "
The remote web server is vulnerable to a path traversal vulnerability.

An attacker may exploit this flaw to read arbitrary files on the remote
system with the privileges of the http process.

Requesting the file c:\boot.ini returns :

" + rep + "

Solution: upgrade your web server or change it.";

	security_message(port:port, data:txt);
  }

  http_close_socket(soc);
 }
}
