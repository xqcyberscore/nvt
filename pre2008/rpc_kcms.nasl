# OpenVAS Vulnerability Test
# $Id: rpc_kcms.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Kcms Profile Server
#
# Authors:
# Michael Scheidell  <scheidell at secnap.net>
# based on a script written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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

tag_summary = "The Kodak Color Management System service is running.
The KCMS service on Solaris 2.5 could allow a local user
to write to arbitrary files and gain root access.

*** This warning may be a false 
*** positive since the presence
*** of the bug has not been tested.

Patches: 107337-02 SunOS 5.7 has been released
and the following should be out soon:
111400-01 SunOS 5.8, 111401-01 SunOS 5.8_x86";

tag_solution = "Disable suid, side effects are minimal.
http://www.eeye.com/html/Research/Advisories/AD20010409.html 
http://www.securityfocus.com/bid/2605";

if(description)
{
 script_id(10832);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2605);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_cve_id("CVE-2001-0595");

 name = "Kcms Profile Server";
 script_name(name);
 
 
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2002 Michael Scheidell");

 family = "RPC"; 
 script_family(family);
 script_dependencies("secpod_rpc_portmap.nasl", "os_detection.nasl");
 script_require_keys("rpc/portmap");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://packetstorm.decepticons.org/advisories/ibm-ers/96-09");
 exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("byte_func.inc");

version = get_kb_item("ssh/login/solosversion");
if ( version && ereg(pattern:"5\.1[0-9]", string:version)) exit(0);

RPC_PROG = 100221;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
	port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
	tcp = 1;
	}

if(port){
  if (host_runs("Solaris (2\.[56]|[7-9])") != "no")
    if(tcp)
      security_message(port);
    else
      security_message(port, protocol:"udp");
}
