# OpenVAS Vulnerability Test
# $Id: DDI_LanRover_Blank_Password.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Shiva LanRover Blank Password
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2002 Digital Defense Incorporated
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

tag_summary = "The Shiva LanRover has no password set for the
root user account. An attacker is able to telnet
to this system and gain access to any phone lines
attached to this device. Additionally, the LanRover
can be used as a relay point for further attacks
via the telnet and rlogin functionality available
from the administration shell.";

tag_solution = "Telnet to this device and change the
password for the root account via the passwd
command. Please ensure any other accounts have
strong passwords set.";

if(description)
{
 script_id(10998);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-1999-0508");
 
 
 name = "Shiva LanRover Blank Password";
 
 script_name(name);
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2002 Digital Defense Incorporated");

 family = "Privilege escalation";

 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/telnet", 23);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include('telnet_func.inc');
port = 23;
if(!get_port_state(port))exit(0);

banner = get_telnet_banner(port:port);
if ( ! banner || "@ Userid:" >!< banner ) exit(0);

soc = open_sock_tcp(port);

if(soc)
{
    r = telnet_negotiate(socket:soc);

    if("@ Userid:" >< r)
    { 
        send(socket:soc, data:string("root\r\n"));
        r = recv(socket:soc, length:4096);
        
        if("Password?" >< r)
        {
            send(socket:soc, data:string("\r\n"));
            r = recv(socket:soc, length:4096);

            if ("Shiva LanRover" >< r)
            {
                security_message(port:port);
            }
       }
    }
    close(soc);
}
