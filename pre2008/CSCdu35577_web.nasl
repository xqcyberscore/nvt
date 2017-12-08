# OpenVAS Vulnerability Test
# $Id: CSCdu35577_web.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Cisco bug ID CSCdu35577 (Web Check)
#
# Authors:
# Michael J. Richardson <michael.richardson@protiviti.com>
#
# Copyright:
# Copyright (C) 2004 Michael J. Richardson
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

tag_summary = "The remote VPN concentrator gives out too much information in application 
layer banners.  

An incorrect page request provides the specific version of software installed.

This vulnerability is documented as Cisco bug ID CSCdu35577.";

tag_solution = "http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml";

if(description)
{
  script_id(14718);
  script_version("$Revision: 8023 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5624);
  script_cve_id("CVE-2002-1094");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  name = "Cisco bug ID CSCdu35577 (Web Check)";

  script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 
 script_copyright("This script is Copyright (C) 2004 Michael J. Richardson");
 family = "CISCO";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))
  exit(0);


req = http_get(item:"/this_page_should_not_exist.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) 
  exit(0);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) && "<b>Software Version:</b> >< res" && "Cisco Systems, Inc./VPN 3000 Concentrator Version" >< res)
  {
    data = "
The remote VPN concentrator gives out too much information in application layer banners.  

An incorrect page request provides the specific version of software installed.

The following Software Version was identified:

" +
  egrep(pattern:"Cisco Systems, Inc./VPN 3000 Concentrator Version", string:res) + "
This vulnerability is documented as Cisco bug ID CSCdu35577.

Solution: 
http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml";

    security_message(port:port, data:data);
    exit(0);
  }
