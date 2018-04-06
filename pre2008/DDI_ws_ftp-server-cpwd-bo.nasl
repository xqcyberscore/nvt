# OpenVAS Vulnerability Test
# $Id: DDI_ws_ftp-server-cpwd-bo.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: WS_FTP SITE CPWD Buffer Overflow
#
# Authors:
# Forrest Rae <forrest.rae@digitaldefense.net>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2002 Digital Defense, Inc.
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

tag_summary = "This host is running a version of WS_FTP FTP server prior to 3.1.2.  
Versions earlier than 3.1.2 contain an unchecked buffer in routines that 
handle the 'CPWD' command arguments.  The 'CPWD' command allows remote 
users to change their password.  By issuing a malformed argument to the 
CPWD command, a user could overflow a buffer and execute arbitrary code 
on this host.  Note that a local user account is required.

The vendor has released a patch that fixes this issue.  Please install 
the latest patch available from the vendor's website at 
http://www.ipswitch.com/support/.";

# Reference: www.atstake.com/research/advisories/2002/a080802-1.txt

if(description)
{
	script_oid("1.3.6.1.4.1.25623.1.0.11098");
	script_version("$Revision: 9348 $");
	script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
	script_bugtraq_id(5427);
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
	script_cve_id("CVE-2002-0826");
	name = "WS_FTP SITE CPWD Buffer Overflow";
	script_name(name);
		 
	script_category(ACT_GATHER_INFO);
    script_tag(name:"qod_type", value:"remote_banner"); 
	script_family("FTP");
	script_copyright("This script is Copyright (C) 2002 Digital Defense, Inc.");
	script_dependencies("find_service_3digits.nasl");
	script_require_ports("Services/ftp", 21);
 script_tag(name : "summary" , value : tag_summary);
	exit(0);
}

#
# The script code starts here : 
#

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_kb_item(string("ftp/banner/", port));

if(!banner)
{ 
	soc = open_sock_tcp(port);
	if(!soc)exit(0);
	banner = recv_line(socket:soc, length:4096);
}

if(banner)
{
	if(egrep(pattern:".*WS_FTP Server (((1|2)\..*)|(3\.((0(\..*){0,1})|(1\.1))))", string:banner))
	    		security_message(port:port);		
}

