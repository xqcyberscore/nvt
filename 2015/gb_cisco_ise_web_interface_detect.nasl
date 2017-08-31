###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ise_web_interface_detect.nasl 6600 2017-07-07 09:58:31Z teissa $
#
# Cisco Identity Services Engine Web Interface Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105472");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 6600 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:58:31 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2015-12-01 15:47:56 +0100 (Tue, 01 Dec 2015)");
 script_name("Cisco Identity Services Engine Web Interface Detection");

 script_tag(name: "summary" , value: "This script performs HTTP based detection of the Cisco Identity Services Engine Web Interface.");

 script_tag(name:"qod_type", value:"remote_banner");

 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:443 );

url = '/admin/login.jsp';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Identity Services Engine</title>" >< buf && "Cisco Systems" >< buf && 'productName="Identity Services Engine"' >< buf )
{
  register_product( cpe:'cpe:/a:cisco:identity_services_engine' );
  set_kb_item( name:"cisco_ise/webgui_installed", value:TRUE );
  set_kb_item( name:"cisco_ise/webgui_port", value:port );
  log_message( port:port, data:'The Cisco Identity Services Engine Web Interface is running at this port.' );
  exit( 0 );
}

exit( 0 );
