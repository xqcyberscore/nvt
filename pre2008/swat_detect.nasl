# OpenVAS Vulnerability Test
# $Id: swat_detect.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Detect SWAT server port
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modifications by Renaud Deraison :
# - script_require_ports(), script_dependencies()
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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

tag_summary = "SWAT (Samba Web Administration Tool) is running on this port.

SWAT allows Samba users to change their passwords, and offers to the sysadmin 
an easy-to-use GUI to configure Samba.

However, it is not recommended to let SWAT be accessed by the world, as it 
allows an intruder to attempt to brute force some accounts passwords.

In addition to this, the traffic between SWAT and web clients is not ciphered, 
so an eavesdropper can gain clear text passwords easily.";

tag_solution = "Disable SWAT access from the outside network by making your firewall
filter this port.

If you do not need SWAT, disable it by commenting the relevant /etc/inetd.conf 
line.";


if(description)
{
 script_id(10273);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1872);
script_cve_id("CVE-2000-0935");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 
 
 name = "Detect SWAT server port";
 script_name(name);
 


 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2000 SecuriTeam");
 script_family("Service detection");

 script_dependencies("find_service.nasl");
 script_require_ports("Services/swat", 901);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("misc_func.inc");

port = get_kb_item("Services/swat");
if(!port){
	nosvc = 1;
	port = 901;
	}
if (get_port_state(port))
{
 soctcp901 = http_open_socket(port);

 if (soctcp901)
 {
  sendata = http_get(item:"/", port:port);
  send(socket:soctcp901, data:sendata);
  banner = http_recv(socket:soctcp901);
  quote = raw_string(0x22);
  
  expect = "WWW-Authenticate: Basic realm=" + quote + "SWAT" + quote;
  
  if (expect >< banner)
  {
    security_message(port);
    if ( nosvc ) register_service(proto:"swat", port:port);
  }
  http_close_socket(soctcp901);
 }
}
