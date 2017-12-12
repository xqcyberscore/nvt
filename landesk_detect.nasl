###############################################################################
# OpenVAS Vulnerability Test
# $Id: landesk_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# Landesk Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Detection of LANDesk Management Agent";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100328";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8078 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("Landesk Detection");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports(9595, 9593);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");
include("host_details.inc");

## Constant values
SCRIPT_DESC = "Landesk Detection";

port  = 9595;
port1 = 9593;

if(!get_port_state(port))exit(0);
if(!get_port_state(port1))exit(0);

soc = open_sock_tcp(port1);
if(!soc)exit(0);
close(soc);

 url = string("/");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL )continue;

 if(egrep(pattern: "LANDesk.*Management Agent", string: buf, icase: TRUE))
 {
    set_kb_item(name: string("www/", port, "/landesk"), value: TRUE);
  
    cpe = 'cpe:/a:landesk:landesk_management_suite';
    register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:port);
    register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:port1);

    register_service(port:port,  ipproto:"tcp", proto:"landesk");
    register_service(port:port1, ipproto:"tcp", proto:"landesk");

    log_message(data: build_detection_report(app:"LANDesk Management Agent", version:NULL, install:"/", cpe:cpe, concluded: "HTTP Request"),
                port:port);

    log_message(data: build_detection_report(app:"LANDesk Management Agent", version:NULL, install:"/", cpe:cpe, concluded: "HTTP Request"),
                port:port1);
     exit(0);
 }

exit(0);

