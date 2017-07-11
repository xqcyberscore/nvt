###############################################################################
# OpenVAS Vulnerability Test
# $Id: unknown_services.nasl 6294 2017-06-08 18:11:49Z cfischer $
#
# Report banner of unknown services
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11154");
  script_version("$Revision: 6294 $");
  script_tag(name:"last_modification", value:"$Date: 2017-06-08 20:11:49 +0200 (Thu, 08 Jun 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Report banner of unknown services");
  script_category(ACT_END);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Service detection");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin reports the banner from unknown services so that
  the OpenVAS team can take them into account.");

  script_tag(name:"qod_type", value:"remote_banner"); 

  exit(0);
}

include("misc_func.inc");
include("dump.inc");

function unknown_banner_report( port ) {

  local_var banner, method, port;

  if( ! port ) return;

  foreach method( make_list( "spontaneous", "get_http", "help" ) ) {
    banner = get_kb_item( "FindService/tcp/" + port + "/" + method );
    if( banner ) {
      return( make_list( method, banner ) );
    }
  }

  banner = get_kb_item( "unknown/banner/" + port );
  if( banner ) return( make_list( "unknown", banner ) );

  # TBD: Where is this kb item coming from?
  banner = get_kb_item( "Banner/" + port );
  if( banner ) return( make_list( "unknown", banner ) );
}

port = get_kb_item( "Services/unknown" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( port == 139 ) exit( 0 ); # Avoid silly messages
if( ! service_is_unknown( port:port ) ) exit( 0 );

banner = unknown_banner_report( port:port );
if( ! banner ) exit( 0 );

if( strlen( banner[1] ) >= 3 ) {
  hexbanner = hexdump( ddata:banner[1] );
  report = 'An unknown service is running on this port. If you know this service, please ';
  report += 'send the following banner to openvas-plugins@wald.intevation.org:\n\n';
  report += 'Method: ' + banner[0] + '\n\n' + hexbanner;
  log_message( port:port, data:report );
}

exit( 0 );