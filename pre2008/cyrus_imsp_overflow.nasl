# OpenVAS Vulnerability Test
# $Id: cyrus_imsp_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: cyrus-imsp abook_dbname buffer overflow
#
# Authors:
# Noam Rathaus <noam@beyondsecurity.com>
# Changes by rd :
# - description
# - minor bugfixes
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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

tag_summary = "The remote host is running a version of cyrus-imsp (Internet Message Support
Protocol) which has a buffer overflow bug.

An attacker could exploit this bug to execute arbitrary code on this system
with the privileges of the root user.

The overflow occurs when the user issues a too long argument as his name, 
causing an overflow in the abook_dbname function command.";

tag_solution = "Upgrade cyrus-imsp server to version version 1.6a4 or 1.7a";

# From: Felix Lindner [felix.lindner@nruns.com]
# Subject: Cyrus IMSP remote root vulnerability
# Date: Monday 15/12/2003 20:56

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11953");
 script_version("$Revision: 9348 $");
 script_bugtraq_id(9227);
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 
 name = "cyrus-imsp abook_dbname buffer overflow";
 script_name(name);


 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

 script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
 
 family = "Gain a shell remotely";
 
 script_family(family);
	       
 script_dependencies("find_service.nasl");
 script_require_ports("Services/imsp", 406);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#


port = get_kb_item("Services/imsp");
if(!port)port = 406;
# display("port: ", port, "\n");

if(get_port_state(port))
 { 
#  display("connected\n");
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  banner = recv_line(socket:soc, length:4096);
  close(soc);
}

# display("banner: ", banner, "\n");

if(banner)
{
 if( ereg(pattern:".* Cyrus IMSP version (0\..*|1\.[0-5]|1\.6|1\.6a[0-3]|1\.7) ready", string:banner) )
 {
  security_message(port);
 }
}
