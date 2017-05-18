###############################################################################
# OpenVAS Vulnerability Test
# $Id: zabbix_detect.nasl 5877 2017-04-06 09:01:48Z teissa $
#
# ZABBIX Server Detection
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

tag_summary = "Detection of ZABBIX Server.
The script sends a connection request to the server and attempts to
identify the service from the reply.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100403";

if (description)
{
 script_id(100403);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5877 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-06 11:01:48 +0200 (Thu, 06 Apr 2017) $");
 script_tag(name:"creation_date", value:"2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("ZABBIX Server Detection");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/unknown", 10051);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("host_details.inc");

port = get_unknown_port( default:10051 );

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = string("ZBX_GET_HISTORY_LAST_ID");
send(socket:soc, data:req);

buf = recv(socket:soc, length:1024);
close(soc);

if(isnull(buf))exit(0);

if("ZBXD" >< buf) {
  
  register_service(port:port, ipproto:"tcp", proto:"zabbix_server");
  set_kb_item(name:"Zabbix/installed", value:TRUE);

  cpe = 'cpe:/a:zabbix:zabbix';

  register_product(cpe:cpe, location:port +'/tcp', nvt:SCRIPT_OID, port:port);

  log_message(data: build_detection_report(app:"Zabbix Server", version:'unknown', install:port + '/tcp', cpe:cpe, concluded: buf),
              port:port);

  exit(0);
}

exit(0);
