# OpenVAS Vulnerability Test
# $Id: inn_buff_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: INN buffer overflow
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

tag_summary = "The remote host is running INN (InterNetNews).

The remote version of this server does not do proper bounds checking. 
An attacker may exploit this issue to crash the remote service by overflowing
some of the buffers by sending a maliciously formatted news article.";

tag_solution = "Upgrade to version 2.2.2 of this service or newer";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.14683");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_bugtraq_id(1249);
 script_xref(name:"OSVDB", value:"1353");
 script_cve_id("CVE-2000-0360");
 
 name = "INN buffer overflow";
 script_name(name);
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Buffer overflow";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/nntp", 119);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

port = get_kb_item("Services/nntp");
if(!port) port = 119;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
  if(soc)
  {
    r = recv_line(socket:soc, length:1024);
    if ( r == NULL ) exit(0);
    #check for version 2.0.0 to 2.2.1
    if(egrep(string:r, pattern:"^20[0-9] .* INN 2\.(([0-1]\..*)|(2\.[0-1][^0-9])) .*$"))
    {
      security_message(port);
    }
  }
}
