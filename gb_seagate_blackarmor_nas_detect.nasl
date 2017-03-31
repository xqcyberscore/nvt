###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seagate_blackarmor_nas_detect.nasl 5499 2017-03-06 13:06:09Z teissa $
#
# Seagate Blackarmor NAS Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103753";   

if (description)
{
 
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 5499 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2017-03-06 14:06:09 +0100 (Mon, 06 Mar 2017) $");
 script_tag(name:"qod_type", value:"remote_banner");
 script_tag(name:"creation_date", value:"2013-08-08 17:20:17 +0200 (Thu, 08 Aug 2013)");
 script_name("Seagate Blackarmor NAS Detection");

 tag_summary =
   "The script sends a connection request to the server and attempts to
    detect if the remote host is a Seagate NAS from the reply.";


 script_tag(name : "summary" , value : tag_summary);


 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = "/index.php";
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Seagate NAS" >!< buf || "p_user" >!< buf)exit(0);

set_kb_item(name:"seagate_nas/installed",value:TRUE);
cpe = 'cpe:/h:seagate:blackarmor_nas';

register_product(cpe:cpe, location:'/', nvt:SCRIPT_OID, port:port);

log_message(data:'The remote host is a Seagate NAS.\nCPE: ' + cpe, port:port);
exit(0);

