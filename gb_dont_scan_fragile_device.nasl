###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dont_scan_fragile_device.nasl 7929 2017-11-29 09:59:29Z cfischer $
#
# Do not scan fragile devices
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108298");
  script_version("$Revision: 7929 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-29 10:59:29 +0100 (Wed, 29 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-24 14:08:04 +0100 (Fri, 24 Nov 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Do not scan fragile devices");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Settings");
  script_dependencies("global_settings.nasl");
  script_mandatory_keys("global_settings/exclude_fragile");

  script_tag(name:"summary", value:"This script checks if the remote host is a 'fragile' device
  known to be crashing / showing an unexpected behavior if scanned. It will output more info
  if a specific port or the whole device was excluded from the scan.

  It is possible to disable this by setting the preference 'Exclude known fragile devices/ports from scan'
  within the 'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) to 'no'.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");

if( get_kb_item( "Host/scanned" ) == 0 ) exit( 0 );
if( ! get_kb_item( "global_settings/exclude_fragile" ) ) exit( 0 );

# nb: exclude_from_tls is causing that the port is not even touched by SSL/TLS tests
function fragile_exclude_and_report( reason, port, mark_dead, exclude_from_tls ) {

  local_var reason, port, mark_dead, exclude_from_tls, exclude_port_text, mark_dead_text, enable_text;

  exclude_port_text = 'This port was excluded from the scan because of the following reason:\n\n';
  mark_dead_text    = 'The scan has been disabled against this host because of the following reason:\n\n';
  enable_text       = '\n\nIf you want to disable this behavior please set the preference "Exclude known fragile devices/ports from scan" ';
  enable_text      += ' within the "Global variable settings" (OID: 1.3.6.1.4.1.25623.1.0.12288) to "no".';

  if( mark_dead ) {
    log_message( data:mark_dead_text + reason + enable_text );
    set_kb_item( name:"Host/dead", value:TRUE );
    exit( 0 );
  }

  if( get_port_state( port ) ) {
    if( exclude_from_tls ) set_kb_item( name:"fragile_port/exclude_tls/" + port, value:TRUE );
    register_service( port:port, proto:"fragile_port" );
    replace_kb_item( name:"BannerHex/" + port, value:"aeaeaeaeae" );
    replace_kb_item( name:"Banner/" + port, value:"ignore-this-banner" );
    log_message( port:port, data:exclude_port_text + reason + enable_text );
    exit( 0 );
  }
}

# Lantronix devices on telnet 9999/tcp
# This device is known to break if port 30718/tcp is touched
port = 9999;
if( get_port_state( port ) ) {
  banner = get_telnet_banner( port:port );
  if( banner && ( banner =~ "Lantronix .* Device Server" || ( "MAC address " >< banner && "Software version " >< banner ) ) ) {
    fragile_exclude_and_report( reason:"- The detected Lantronix Device is known to crash if this port is scanned.", port:30718, exclude_from_tls:TRUE );
  }
}

# Same Lantronix devices above but check directly 30718/udp
port = 30718;
if( get_udp_port_state( port ) ) {
  soc = open_sock_udp( port );
  if( soc ) {
    req = raw_string( 0x00, 0x00, 0x00, 0xF8 );
    send( socket:soc, data:req );
    recv = recv( socket:soc, length:124 );
    close( soc );
    if( recv && strlen( recv ) == 124 && hexstr( substr( recv, 0, 3 ) ) == "000000f9" ) {
      fragile_exclude_and_report( reason:"- The detected Lantronix Device is known to crash if this port is scanned.", port:30718, exclude_from_tls:TRUE );
    }
  }
}

# And the same for 30718/tcp
port = 30718;
if( get_port_state( port ) ) {
  soc = open_sock_tcp( port );
  if( soc ) {
    req = raw_string( 0x00, 0x00, 0x00, 0xF8 );
    send( socket:soc, data:req );
    recv = recv( socket:soc, length:124 );
    close( soc );
    if( recv && strlen( recv ) == 124 && hexstr( substr( recv, 0, 3 ) ) == "000000f9" ) {
      fragile_exclude_and_report( reason:"- The detected Lantronix Device is known to crash if this port is scanned.", port:30718, exclude_from_tls:TRUE );
    }
  }
}

exit( 0 );