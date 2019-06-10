###############################################################################
# OpenVAS Vulnerability Test
#
# Vicon Industries Network Camera Detection (Telnet)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107334");
  script_version("2019-06-06T07:39:31+0000");
  script_tag(name:"last_modification", value:"2019-06-06 07:39:31 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2018-07-23 11:32:40 +0200 (Mon, 23 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Vicon Industries Network Camera Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/vicon_industries/network_camera/detected");

  script_tag(name:"summary", value:"This script performs Telnet based detection of Vicon Industries Network Cameras.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("misc_func.inc");
include("dump.inc");
include("telnet_func.inc");
include("host_details.inc");

port   = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );

if( egrep( string:banner, pattern:"^IQinVision .* Version ", icase:FALSE ) ||
    ( banner =~ "IQinVision " && banner =~ "Type HELP at the .* prompt for assistance" ) ) {

  set_kb_item( name:"vicon_industries/network_camera/detected", value:TRUE );
  set_kb_item( name:"vicon_industries/network_camera/telnet/detected", value:TRUE );
  set_kb_item( name:"vicon_industries/network_camera/telnet/port", value:port );
}
  version = "unknown";

  vers = eregmatch( pattern:"(Software version|Version) [VB]?([0-9.]+)", string:banner );

  if( vers[2] ) {
    version = vers[2];
    set_kb_item( name:"vicon_industries/network_camera/telnet/" + port + "/concluded", value:vers[0] );
  } else {
    set_kb_item( name:"vicon_industries/network_camera/telnet/" + port + "/concluded", value:bin2string( ddata:banner, noprint_replacement:'' ) );
  }
  set_kb_item( name:"vicon_industries/network_camera/telnet/" + port + "/version", value:version );

  type = "unknown";

  type = eregmatch( pattern:"IQ(eye)?([0578ADMPR])", string:banner );

  type_list['0'] = "3 Series / 4 Series";
  type_list['5'] = "5 Series";
  type_list['7'] = "7 Series";
  type_list['8'] = "Sentinel Series";
  type_list['9'] = "9 Series";
  type_list['A'] = "Alliance-pro";
  type_list['D'] = "Alliance-mini";
  type_list['M'] = "Alliance-mx";
  type_list['P'] = "PTZ";
  type_list['R'] = "R5 series";

  if( type_list[type[2]] ) {
    type = type_list[type[2]];

  } else {
    type = "unknown";
    }

  if( "IQinVision" >!< banner && "Software version " >< banner && "MAC address " >< banner ) {
    type = "Branded";
  }

  if ( type == "unknown" ) {
    username = "login";
    access = FALSE;

    soc = open_sock_tcp( port );
    if( soc ) {

      recv1 = recv( socket:soc, length:2048, timeout:10 );

      if ( "prompt for assistance" >< recv1 && "Username>" >< recv1 ) {
        send( socket:soc, data:username + '\r\n' );
        recv2 = recv( socket:soc, length:2048, timeout:10 );

        if ( recv2 =~ "Local_.+>" ) {
          access = TRUE;
          set_kb_item(name:"vicon_industries/network_camera/telnet/" + port + "/access", value:TRUE );
        }
      }

      if ( access ) {
        send( socket:soc, data:'show server\r\n' );
        recv3 = recv( socket:soc, length:2048, timeout:10 );
        typerecv = eregmatch( pattern: "(Software version|Version) [VB]?([0-9.]+)", string:bin2string( ddata:recv3, noprint_replacement:'' ) );
        if(!isnull(typerecv[1])){
          type = typerecv[1];
        }
      }
      close( soc );
    }
    exit( 0 );
  }

  set_kb_item( name:"vicon_industries/network_camera/telnet/" + port + "/type", value:type );

  if( mac = eregmatch( pattern:"MAC address ([0-9a-fA-F]{12})", string:bin2string( ddata:banner, noprint_replacement:'' ) ) ) {
    plain_mac = mac[1];
    for( i = 0; i < 12; i++ ) {
      full_mac += plain_mac[i];
      if( i % 2 && i != 11 ) full_mac += ":";
    }
    register_host_detail( name:"MAC", value:full_mac, desc:"Get the MAC Address via Telnet banner" );
    replace_kb_item( name:"Host/mac_address", value:full_mac );
}
exit( 0 );