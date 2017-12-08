# OpenVAS Vulnerability Test
# $Id: w32_spybot_worm_variant.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: w32.spybot.fcd worm infection
#
# Authors:
# Jorge E Rodriguez <KPMG>
# 	- check the system for infected w32.spybot.fbg
#	- script id
#	- cve id
#
# Copyright:
# Copyright (C) 2004 jorge rodriguez
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

tag_summary = "The remote system is infected with a variant of the worm w32.spybot.fcd. 

Infected systems will scan systems that are vulnerable in the same subnet
in order to attempt to spread.

This worm also tries to do DDoS against targets in the Internet.";

tag_solution = "ensure all MS patches are applied as well as the latest AV
definitions.";

if(description)
{
 script_id(15520);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 
 name = "w32.spybot.fcd worm infection";
 script_name(name);
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
 
 
 script_copyright("This script is Copyright (C) 2004 jorge rodriguez");
 family = "Malware";
 script_family(family);
 script_dependencies("find_service1.nasl", "os_detection.nasl");
 script_require_ports(113);
 script_exclude_keys('fake_identd/113');
 script_mandatory_keys("Host/runs_windows");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://securityresponse.symantec.com/avcenter/venc/data/w32.spybot.fcd.html");
 exit(0);
}

include('misc_func.inc');
include('host_details.inc');

if (get_kb_item('fake_identd/113')) exit(0);

if(get_port_state(113))
{
 soc = open_sock_tcp(113);
 if(soc)
 {
  req = string("GET\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:16000);
  if(" : USERID : UNIX :" >< r) {
	if ( "GET : USERID : UNIX :" >< r ) exit(0);
	security_message(113);
	if (service_is_unknown(port: 113))
	  register_service(port: port, proto: 'fake-identd');
	set_kb_item(name: 'fake_identd/113', value: TRUE);
	}
  close(soc);
 }
}
