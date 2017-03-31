###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_prime_data_center_network_manager_detect.nasl 2622 2016-02-09 13:03:15Z antu123 $
#
# Cisco Prime Data Center Network Manager Detection
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
 script_oid("1.3.6.1.4.1.25623.1.0.105255");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 2622 $");
 script_tag(name:"last_modification", value:"$Date: 2016-02-09 14:03:15 +0100 (Tue, 09 Feb 2016) $");
 script_tag(name:"creation_date", value:"2015-04-14 12:45:24 +0200 (Tue, 14 Apr 2015)");
 script_name("Cisco Prime Data Center Network Manager Detection");

 script_tag(name: "summary" , value: "The script sends a connection
request to the server and attempts to extract the version number
from the reply.");

 script_tag(name:"qod_type", value:"remote_banner");

 script_summary("Checks for the presence of Cisco Prime Data Center Network Manager");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

url = '/';
install = url;

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Data Center Network Manager</title>" >!< buf || 'productFamily">Cisco Prime' >!< buf ) exit( 0 );

set_kb_item(name:"cisco_prime_dcnm/installed",value:TRUE);
cpe = ' cpe:/a:cisco:prime_data_center_network_manager';

vers = 'unknown';

version = eregmatch( pattern:'productVersion">Version: ([^<]+)<', string:buf ); # For example: 7.1(1)
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + version[1];
  set_kb_item( name:"cisco_prime_dcnm/version", value:version[1]);
}

register_product( cpe:cpe, location:install, port:port );

log_message( data: build_detection_report( app:"Cisco Prime Data Center Network Manager",
                                           version:vers,
                                           install:install,
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:port );


exit(0);

