# OpenVAS Vulnerability Test
# $Id: ssh_forwarding.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: OpenSSH Client Unauthorized Remote Forwarding
#
# Authors:
# Xue Yong Zhi<xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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

tag_summary = "You are running OpenSSH SSH client before 2.3.0.
 
This version  does not properly disable X11 or agent forwarding, 
which could allow a malicious SSH server to gain access to the X11 
display and sniff X11 events, or gain access to the ssh-agent.";

tag_solution = "Patch and New version are available from OpenSSH.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11343");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1949);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2000-1169");
 
 name = "OpenSSH Client Unauthorized Remote Forwarding";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
 
 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);

	
# Looking for OpenSSH product version number < 2.3
if(ereg(pattern:".*openssh[_-](1|2\.[0-2])\..*",string:tolower(banner)))security_message(port);
	
	

