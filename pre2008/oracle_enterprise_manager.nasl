# OpenVAS Vulnerability Test
# $Id: oracle_enterprise_manager.nasl 9584 2018-04-24 10:34:07Z jschulte $
# Description: Oracle Enterprise Manager
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "Detection of Oracle Enterprise Manager

The script sends a connection request to the server and attempts to
detect Oracle Enterprise Manager from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.17586";

if(description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9584 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Oracle Enterprise Manager");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_probe");
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_family("Product detection");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 5500, 1158);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:1158);
if(get_port_state(port))
{
 url = "/em/console/logon/logon";
 req = http_get(item:url, port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);

 if ("<title>Oracle Enterprise Manager</title>" >< rep)
 {

   set_kb_item(name: string("www/", port, "/oracle_enterprise_manager"), value: string("unknown under ",url));
   set_kb_item(name:"oracle_enterprise_manager/installed",value:TRUE);

   cpe = 'cpe:/a:oracle:enterprise_manager';
   register_product(cpe:cpe, location:url, port:port);

   log_message(data: build_detection_report(app:"Oracle Enterprise Manager", version:"unknown", install:url, cpe:cpe, concluded: "<title>Oracle Enterprise Manager</title>"),
               port:port);

   exit(0);

 }
}
