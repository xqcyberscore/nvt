# OpenVAS Vulnerability Test
# $Id: helix_overflow.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Helix RealServer Buffer Overrun
#
# Authors:
# Keith Young
#
# Copyright:
# Copyright (C) 2003 Montgomery County Maryland Government Security Team
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

tag_summary = "RealServer 8.0 and earlier and Helix Server 9.0 is 
vulnerable to a buffer overflow.

More information and patches can be downloaded from
http://service.real.com/help/faq/security/bufferoverrun030303.html";

tag_solution = "Install patches from vendor";

if(description)
{
 script_id(11642);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8476);
 script_cve_id("CVE-2003-0725");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 
 name = "Helix RealServer Buffer Overrun";
 script_name(name);
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2003 Montgomery County Maryland Government Security Team");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/rtsp", 554);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# Open the connection on port 554 and send the OPTIONS string
#

 port = get_kb_item("Services/rtsp");
 if(!port)port = 554;
 if (get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
   data = string("OPTIONS * RTSP/1.0\r\n\r\n");
   send(socket:soc, data:data);
   header = recv(socket:soc, length:1024);
   if(("RTSP/1" >< header) && ("Server:" >< header)) {
     server = egrep(pattern:"Server:",string:header);

# Currently, all versions up to and including 9.0.1 are affected

     if( (egrep(pattern:"Version [0-8]\.[0-9]", string:server)) ||
         (egrep(pattern:"Version 9\.0\.[0-1]", string:server)) ) {
      security_message(port);
     }
   }
  close(soc);
  }
 }
