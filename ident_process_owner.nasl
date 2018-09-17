###############################################################################
# OpenVAS Vulnerability Test
# $Id: ident_process_owner.nasl 11399 2018-09-15 07:45:12Z cfischer $
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
  script_version("$Revision: 11399 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 09:45:12 +0200 (Sat, 15 Sep 2018) $");
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
  #  script_exclude_keys("Host/ident_scanned");

  script_tag(name:"summary", value:"This plugin uses identd (RFC 1413) to determine which user is
  running each service");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

SCRIPT_DESC = "Identd scan";
banner_type = "Identd scan OS report";

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
os_reported = FALSE;

# nb: Try several times, as some ident daemons limit the throughput of answers?!
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
        res = recv_line( socket:isoc, length:1024 );
        if( res ) {
          _res = split( chomp( res ), sep:":" );
          os = chomp( _res[2] );
          id = chomp( _res[3] );
          # e.g.
          # 53,35089:USERID:UNIX:pdns
          # 113 , 60954 : USERID : 20 : oidentd
          # see also https://tools.ietf.org/html/rfc1413
          if( "USERID" >< _res[1] && strlen( id ) < 30 ) {
            identd_n++;
            set_kb_item( name:"Ident/tcp/" + port, value:id );
            report  = "identd reveals that this service is running as user '" + id + "'.";
            report += ' Response:\n\n' + res;
            log_message( port:port, data:report );

            # nb: try go gather the Host OS. See https://www.iana.org/assignments/operating-system-names/operating-system-names.xhtml#operating-system-names-1 for identifiers
            # nb: Some ident services are just reporting a number
            if( os && ! egrep( string:os, pattern:"^[0-9]+$" ) && ! os_reported ) {
              os = tolower( os );
              if( "windows" >< os || "win32" >< os ) {
                register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, banner:res, port:iport, desc:SCRIPT_DESC, runs_key:"windows" );
                os_reported = TRUE;
              } else if( "linux" >< os || "unix" >< os ) {
                register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:res, port:iport, desc:SCRIPT_DESC, runs_key:"unixoide" );
                os_reported = TRUE;
              } else if( "freebsd" >< os ) {
                register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, banner:res, port:iport, desc:SCRIPT_DESC, runs_key:"unixoide" );
                os_reported = TRUE;
              } else {
                if( "unknown" >!< os && "other" >!< os ) {
                  register_unknown_os_banner( banner:res, banner_type_name:banner_type, banner_type_short:"identd_os_banner", port:iport );
                  os_reported = TRUE;
                }
              }
            }
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
