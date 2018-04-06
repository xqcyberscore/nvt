# OpenVAS Vulnerability Test
# $Id: exchange_xexch50_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Exchange XEXCH50 Remote Buffer Overflow
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
# Improved by John Lampe to see if XEXCH is an allowed verb
#
# Copyright:
# Copyright (C) 2003 Digital Defense Inc.
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

tag_solution = "See http://www.microsoft.com/technet/security/bulletin/MS03-046.mspx";
tag_summary = "This system appears to be running a version of the Microsoft Exchange
SMTP service that is vulnerable to a flaw in the XEXCH50 extended verb.
This flaw can be used to completely crash Exchange 5.5 as well as execute
arbitrary code on Exchange 2000. ";

if(description)
{
     script_oid("1.3.6.1.4.1.25623.1.0.11889");
     script_version("$Revision: 9348 $");
     script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
     script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
     script_bugtraq_id(8838);
     script_xref(name:"IAVA", value:"2003-A-0031");
     script_cve_id("CVE-2003-0714");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
     name = "Exchange XEXCH50 Remote Buffer Overflow";
     script_name(name);


		    
 
    summary = "Tests to see if authentication is required for the XEXCH50 command";
 		 
 
    script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 
    script_copyright("This script is Copyright (C) 2003 Digital Defense Inc.");
 
    family = "SMTP problems";
    script_family(family);
    
    script_dependencies("smtpserver_detect.nasl");
    script_exclude_keys("SMTP/wrapped");
    script_require_ports("Services/smtp", 25);
     script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
    exit(0);
}

include("smtp_func.inc");

debug = 0;

port = get_kb_item("Services/smtp");
if(!port) port = 25;

if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

greeting = smtp_recv_banner(socket:soc);
if(debug) display("GREETING: ", greeting, "\n");

# look for the exchange banner, removing this may get us through some proxies
if (! egrep(string:greeting, pattern:"microsoft", icase:TRUE)) exit(0);

send(socket:soc, data:string("EHLO X\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug) display("HELO: ", ok, "\n");
if("XEXCH50" >!< ok)exit(0);

send(socket:soc, data:string("MAIL FROM: Administrator\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug) display("MAIL: ", ok, "\n");

send(socket:soc, data:string("RCPT TO: Administrator\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug) display("RCPT: ", ok, "\n");

send(socket:soc, data:string("XEXCH50 2 2\r\n"));
ok = smtp_recv_line(socket:soc);
if (! ok) exit(0);
if(debug) display("XEXCH50: ", ok, "\n");

if (egrep(string:ok, pattern:"^354 Send binary")) security_message(port:port);

close(soc);
