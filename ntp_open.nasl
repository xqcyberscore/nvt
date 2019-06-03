###############################################################################
# OpenVAS Vulnerability Test
#
# NTP read variables
#
# Authors:
# David Lodge
# Changes by rd:
# - recv() only receives the first two bytes of data (instead of 1024)
# - replaced ord(result[0]) == 0x1E by ord(result[0]) & 0x1E (binary AND)
#
# Copyright:
# Copyright (C) 2005 David Lodge
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
  script_oid("1.3.6.1.4.1.25623.1.0.10884");
  script_version("2019-06-01T08:20:43+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-06-01 08:20:43 +0000 (Sat, 01 Jun 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("NTP read variables");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Lodge");
  script_family("Product detection");
  script_require_udp_ports(123);

  script_tag(name:"summary", value:"This script performs detection of NTP servers.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("misc_func.inc");

SCRIPT_DESC = "NTP read variables";

function ntp_read_list() {

  local_var data, soc, r, p;

  data = raw_string( 0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00 );
  soc = open_sock_udp( port );
  if( ! soc )
    return( NULL );

  send( socket:soc, data:data );
  r = recv( socket:soc, length:4096 );
  close( soc );

  if( ! r )
    return( NULL );

  p = strstr( r, "version=" );
  if( ! p )
    p = strstr( r, "processor=" );

  if( ! p )
    p = strstr( r, "system=" );

  p = ereg_replace( string:p, pattern:raw_string(0x22), replace:"'" );

  if( p )
    return( p );

  return( NULL );
}

function ntp_installed() {

  local_var data, soc, r;

  data = raw_string( 0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01, 0x00, 0x00,
                     0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA, 0x00, 0x00 );

  soc = open_sock_udp( port );
  if( ! soc )
    return( NULL );

  send( socket:soc, data:data );
  r = recv( socket:soc, length:4096 );
  close( soc );

  if( strlen( r ) > 10 )
    return( r );

  return( NULL );
}

port = 123;
banner_type = "NTP banner";

if( ! get_udp_port_state( port ) )
  exit( 0 );

r = ntp_installed();

if( r ) {
  set_kb_item( name:"NTP/Running", value:TRUE );
  register_service( port:port, proto:"ntp", ipproto:"udp" );
  list = ntp_read_list();
  if( ! list ) {
    log_message( port:port, protocol:"udp" );
  } else {
    if( "system" >< list ) {

      s = egrep( pattern:"system=", string:list );
      os = ereg_replace( string:s, pattern:".*system='?([^',]+)[',].*", replace:"\1" );

      set_kb_item( name:"Host/OS/ntp", value:os );
      set_kb_item( name:"ntp/system_banner/available", value:TRUE );
      set_kb_item( name:"ntp/" + port + "/system_banner", value:os );
    }

    if( "processor" >< list ) {
      s = egrep( pattern:"processor=", string:list );
      os = ereg_replace( string:s, pattern:".*processor='?([^',]+)[',].*", replace:"\1" );
      set_kb_item( name:"Host/processor/ntp", value:os );
    }

    if( "ntpd" >< list ) {
      set_kb_item( name:"NTP/Installed", value:TRUE );
      ntpVerFull = eregmatch( pattern:"version='([^']+)',", string:list );
      if( ! isnull( ntpVerFull[1] ) )
        set_kb_item( name:"NTP/Linux/FullVer", value:ntpVerFull[1] );

      ntpVer = eregmatch( pattern:"ntpd ([0-9.]+)([a-z][0-9]+)?-?(RC[0-9]+)?", string:list );

      if( ! isnull( ntpVer[1] ) ) {

        if( ntpVer[2] =~ "[a-z][0-9]+" && ntpVer[3] =~ "RC" ) {
          ntpVer = ntpVer[1] + ntpVer[2] + "." + ntpVer[3];
        } else if( ntpVer[2] =~ "[a-z][0-9]+" ) {
          ntpVer = ntpVer[1] + ntpVer[2];
        } else {
          ntpVer = ntpVer[1];
        }
      } else {
        ntpVer = "unknown";
      }

      set_kb_item( name:"NTP/Linux/Ver", value:ntpVer );

      cpe = build_cpe( value:ntpVer, exp:"^([0-9.]+[a-z0-9A-Z.]+?)", base:"cpe:/a:ntp:ntp:" );
      if( ! cpe )
        cpe = "cpe:/a:ntp:ntp";

      install = port + "/udp";
      register_product( cpe:cpe, location:install, port:port, service:"ntp" );
    }

    report = 'It is possible to determine a lot of information about the remote host by querying ' +
             'the NTP (Network Time Protocol) variables - these include OS descriptor, and time settings.\n\n' +
             'It was possible to gather the following information from the remote NTP host : \n\n' + list + '\n' +
             'Quickfix: Restrict default access to ignore all info packets.';

    log_message( port:port, protocol:"udp", data:report );
    exit( 0 );
  }
}

exit( 0 );
