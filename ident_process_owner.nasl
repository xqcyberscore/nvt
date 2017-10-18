###############################################################################
# OpenVAS Vulnerability Test
# $Id: ident_process_owner.nasl 7447 2017-10-16 14:18:46Z cfischer $
#
# Identd scan
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14674");
  script_version("$Revision: 7447 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-16 16:18:46 +0200 (Mon, 16 Oct 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Identd scan");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service1.nasl", "slident.nasl", "secpod_open_tcp_ports.nasl");
  script_require_ports("Services/auth", 113);
  script_mandatory_keys("TCP/PORTS");
  #script_exclude_keys("Host/ident_scanned");

  script_tag(name:"summary" , value:"This plugin uses identd (RFC 1413) to determine which user is
  running each service");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("misc_func.inc");

#if (get_kb_item("Host/ident_scanned")) exit(0);

ports = get_all_tcp_ports_list();
if( isnull( ports ) ) exit( 0 );

# Should we only use the first found identd?
list = get_kb_list( "Services/auth" );
if( ! isnull( list ) ) {
  list = make_list( 113, list );
} else {
  list = make_list( 113 );
}

foreach iport( list ) {
  if( get_port_state( iport ) && ! get_kb_item( "fake_identd/" + iport ) ) {
    isoc = open_sock_tcp( iport );
    if( isoc ) break;
  }
}

if( ! isoc ) exit( 0 );

identd_n = 0;

# Try several times, as some ident daemons limit the throughput of answers?!
for( i = 1; i <= 6 && ! isnull( ports ); i++ ) {

  prev_ident_n = identd_n;
  j = 0;

  foreach port( ports ) {
    if( get_port_state( port ) && ! get_kb_item( "Ident/tcp" + port ) ) {
      soc = open_sock_tcp( port );
      if( soc ) {
        req = strcat( port, ',', get_source_port( soc ), '\r\n' );
        if( send( socket:isoc, data:req ) <= 0 ) {
          # In case identd does not allow several requests in a raw
          close( isoc );
          isoc = open_sock_tcp( iport );
          if( ! isoc ) {
            close( soc );
            exit( 0 );
          }
          send( socket:isoc, data:req );
        }
        id = recv_line( socket:isoc, length:1024 );
        if( id ) {
          ids = split( id, sep:':' );
          if( "USERID" >< ids[1] && strlen( ids[3] ) < 30 ) {
            identd_n++;
            set_kb_item( name:"Ident/tcp/" + port, value:ids[3] );
            log_message( port:port, data:"identd reveals that this service is running as user " + ids[3] );
          } else {
            bad[j++] = port;
          }
        } else {
          bad[j++] = port;
        }
        close( soc );
      }
    }
  }

  # Exit if we are running in circles
  if( prev_ident_n == identd_n ) break;

  ports = NULL;
  foreach j( bad ) ports[j] = j;
  bad = NULL;
}

close( isoc );
set_kb_item( name:"Host/ident_scanned", value:TRUE );
exit( 0 );