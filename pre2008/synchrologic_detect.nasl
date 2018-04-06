# OpenVAS Vulnerability Test
# $Id: synchrologic_detect.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Synchrologic User account information disclosure
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
# changes by rd: code of the plugin checks for a valid tag in the reply
#
# Copyright:
# Copyright (C) 2003 John Lampe
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

tag_summary = "The remote host seems to be running Synchrologic Email Accelerator

Synchrologic is a product which allows remote PDA users to synch with email,
calendar, etc.

If this server is on an Internet segment (as opposed to internal), you may
wish to tighten the access to the aggregate.asp page.

The server allows anonymous users to look at Top Network user IDs
Example : http://IP_ADDRESS/en/admin/aggregate.asp";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11657");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_name("Synchrologic User account information disclosure");



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2003 John Lampe");
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

req = http_get(item:"/en/admin/aggregate.asp", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

if("/css/rsg_admin_nav.css" >< res)
	security_message(port);
