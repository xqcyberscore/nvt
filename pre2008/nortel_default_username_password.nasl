# OpenVAS Vulnerability Test
# $Id: nortel_default_username_password.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: Nortel Default Username and Password
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

tag_summary = "The username/password combination 'ro/ro' or 'rwa/rwa' are valid.

These username and password are the default ones for many of
Nortel's network devices.";

tag_solution = "Set a strong password for the account";

if(description)
{
 script_id(15715);
 script_version("$Revision: 6046 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Nortel Default Username and Password");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");

 script_family("Privilege escalation");
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 
 script_dependencies("find_service.nasl");
 script_require_ports("Services/ssh", 22);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here : 
#
include("ssh_func.inc");

port = kb_ssh_transport();
if ( ! port || !get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
ret = ssh_login(socket:soc, login:"ro", password:"ro");
close(soc);
if ( ret == 0 ) security_message(port);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
ret = ssh_login(socket:soc, login:"rwa", password:"rwa");
close(soc);
if ( ret == 0 ) security_message(port);

