# OpenVAS Vulnerability Test
# $Id: DDI_IPSwitch-IMail-SMTP-Buffer-Overflow.nasl 6053 2017-05-01 09:02:51Z teissa $
# Description: IPSwitch IMail SMTP Buffer Overflow
#
# Authors:
# Forrest Rae <forrest.rae@digitaldefense.net>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
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

tag_summary = "A vulnerability exists within IMail that
allows remote attackers to gain SYSTEM level
access to servers running IMail's SMTP
daemon (versions 6.06 and below). The
vulnerability stems from the IMail SMTP daemon 
not doing proper bounds checking on various input 
data that gets passed to the IMail Mailing List 
handler code. If an attacker crafts a special 
buffer and sends it to a remote IMail SMTP server 
it is possible that an attacker can remotely execute 
code (commands) on the IMail system.";

tag_solution = "Download the latest patch from
http://ipswitch.com/support/IMail/patch-upgrades.html";

if(description)
{
	script_id(10994);
	script_version("$Revision: 6053 $");
	script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
	script_bugtraq_id(2083, 2651);
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
	script_cve_id("CVE-2001-0039","CVE-2001-0494");

 
 	name = "IPSwitch IMail SMTP Buffer Overflow";
 	script_name(name);
 
 	summary = "IPSwitch IMail SMTP Buffer Overflow";
	script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
	script_copyright("This script is Copyright (C) 2002 Digital Defense, Inc.");
	family = "SMTP problems";
	script_family(family);
	script_dependencies("find_service.nasl");
	script_require_ports(25);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
	exit(0);
}

debug = 0;
ddidata = string("Not Applicable");
port = 25;

if(get_port_state(port))
{
	if(debug == 1) { display("Port ", port, " is open.\n"); }
		

	soc = open_sock_tcp(port);
	if(soc)
	{
		if(debug == 1)
		{
			display("Socket is open.\n");
		}
		
		banner = recv_line(socket:soc, length:4096);
		
		if(debug == 1)
		{
			display("\n---------Results from request ---------\n");
			display(banner);
			display("\n---------End of Results from request ---------\n\n");
		}
		     
		if(
		   egrep(pattern:"IMail 6\.0[1-6] ", string:banner) 	|| 
		   egrep(pattern:"IMail 6\.0 ", string:banner) 		||
		   egrep(pattern:"IMail [1-5]\.", string:banner)
		  )
		{
			if(debug == 1)
			{
				display("SMTP Server is Imail\n");
			}
		
			security_message(port); 
			exit(0);
		}

		close(soc);
	}
	else
	{
		if(debug == 1) { display("Error: Socket didn't open.\n"); }
	}
}



