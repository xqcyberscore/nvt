###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_control_web_interface_detect.nasl 6701 2017-07-12 13:04:06Z cfischer $
#
# Kerio Control Web Interface Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
 script_oid("1.3.6.1.4.1.25623.1.0.140067");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 6701 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 15:04:06 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2016-11-17 12:32:06 +0100 (Thu, 17 Nov 2016)");
 script_name("Kerio Control Web Interface Detection");

 script_tag(name: "summary" , value: "The script performs HTTP based detection of the Kerio Control Web Interface");

 script_tag(name:"qod_type", value:"remote_banner");

 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 4081);
 script_mandatory_keys("KCEWS/banner");

 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:4081 );

banner = get_http_banner( port:port );

if( "Server: Kerio Control Embedded Web Server" >!< banner ) exit( 0 );

set_kb_item( name:"kerio/control/webiface", value:TRUE );

cpe = 'cpe:/a:kerio:control';

register_product( cpe:cpe, location:"/", port:port, service:"www" );

log_message( port:port, data:'The Kerio Connect Web Interface is running at this port\nCPE: ' + cpe + '\n');

exit( 0 );
