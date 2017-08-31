###############################################################################
# OpenVAS Vulnerability Test
# $Id: snmp_detect.nasl 6511 2017-07-04 06:09:14Z ckuersteiner $
#
# A SNMP Agent is running
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd : improved the SNMP detection (done using
# a null community name)
# Changes by Tenable Network Security:
# detect versions 2c and 2u of SNMP protocol
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10265");
  script_version("$Revision: 6511 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-04 08:09:14 +0200 (Tue, 04 Jul 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("A SNMP Agent is running");
  script_category(ACT_SETTINGS);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("SNMP");
  script_dependencies("gb_open_udp_ports.nasl", "gb_snmp_authorization.nasl", "snmp_default_communities.nasl");

  script_tag(name:"summary", value:"This script detects if SNMP is open and if it is possible to connect
  with the given credentials.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("snmp_func.inc");

if( defined_func( "snmpv3_get" ) ) {

  if( ! port = get_kb_item( "UDP/PORTS" ) ) port = 161;
  if( ! get_udp_port_state( port ) ) exit( 0 );

  community = get_kb_item( "SNMP/community" );
  if( ! community || strlen( community ) == 0 ) {
    community = "public";
    pub_comm = TRUE;
  } else {
    v1_v2_creds = TRUE;
  }

  if( check_snmpv1( port:port, community:community ) ) {

    SNMP_v1 = TRUE;
    replace_kb_item( name:"SNMP/V1/working", value:TRUE );
    replace_kb_item( name:"SNMP/working", value:TRUE );
    replace_kb_item( name:"SNMP/prefered_version", value:1 );

    if( pub_comm ) {
      replace_kb_item( name:"SNMP/community", value:community );
      replace_kb_item( name:"SNMP/V2/community", value:community );
    }
  }

  if( check_snmpv2( port:port, community:community ) ) {

    SNMP_v2 = TRUE;
    replace_kb_item( name:"SNMP/V2/working", value:TRUE );
    replace_kb_item( name:"SNMP/working", value:TRUE );
    replace_kb_item( name:"SNMP/prefered_version", value:2 );

    if( pub_comm ) {
      replace_kb_item( name:"SNMP/community", value:community );
      replace_kb_item( name:"SNMP/V2/community", value:community );
    }
  }

  v3check = check_snmpv3( port:port );
  if( v3check == 1 ) {
    SNMP_v3 = TRUE;
    replace_kb_item( name:"SNMP/V3/working", value:TRUE );
    replace_kb_item( name:"SNMP/working", value:TRUE );
    replace_kb_item( name:"SNMP/prefered_version", value:3 );
  } else if( v3check == 2 ) {
    SNMP_v3 = TRUE;
  }

  if( SNMP_v1 || SNMP_v2|| SNMP_v3 ) {

    report = 'A SNMP server is running on this host.\n\n';

    # worked with provided community string
    if( ( SNMP_v1 || SNMP_v2 ) && v1_v2_creds )
      report += 'SNMPv1|v2: It was possible to log in using the provided community string.\n';

    # worked with default community string 'public'
    if( ( SNMP_v1 || SNMP_v2 ) && pub_comm )
      report += 'SNMPv1|v2: It was possible to log in using the default community string \'public\'.\n';

    # Notify the user if the provided community string did not work
    if( ( ! SNMP_v1 || ! SNMP_v2 ) && v1_v2_creds )
      report += 'SNMPv1|v2: It was not possible to log in using the provided community string.\n';

    if( SNMP_v3 ) {
      # correct provided credentials
      if( ! snmp_error ) report += 'SNMPv3: It was possible to log in using the provided credentials.\n';
      else
        # wrong provided credentials
        if( v3_creds ) report += 'SNMPv3: It was not possible to log in using the provided credentials. Error: ' + snmp_error + '\n';
    }

    report += '\nThe following SNMP versions are supported:\n';
    if( SNMP_v1 ) report += 'SNMP v1\n';
    if( SNMP_v2 ) report += 'SNMP v2c\n';
    if( SNMP_v3 ) report += 'SNMP v3\n';

    log_message( port:port, proto:"udp", data:report );
    register_service( port:port, ipproto:"udp", proto:"snmp" );
    replace_kb_item( name:"SNMP/running", value:TRUE );
    exit( 0 );
  }
} else {

  port = 161;
  if( ! ( get_udp_port_state( port ) ) ) exit( 0 );
  socudp161 = open_sock_udp( port );
 
  data = 'A SNMP server is running on this host\nThe following versions are supported\n';
  flag = 0;

  ver[0] = "1";
  ver[1] = "2c";
  ver[2] = "2u";

  community = get_kb_item( "SNMP/community" );
  if( ! community ) community = "public";

  SNMP_BASE = 31;
  COMMUNITY_SIZE = strlen( community );

  sz = COMMUNITY_SIZE % 256;

  len = SNMP_BASE + COMMUNITY_SIZE;
  len_hi = len / 256;
  len_lo = len % 256;

  if( socudp161 ) {
    for( i = 0; i < 3; i++ ) { 

      req = raw_string( 0x30, 0x82, len_hi, len_lo, 
                        0x02, 0x01, i, 0x04,
                        sz );

      req = req + community + 
            raw_string( 0xA1,0x18, 0x02, 
                 0x01, 0x01, 0x02, 0x01, 
                 0x00, 0x02, 0x01, 0x00, 
                 0x30, 0x0D, 0x30, 0x82, 
                 0x00, 0x09, 0x06, 0x05, 
                 0x2B, 0x06, 0x01, 0x02,
                 0x01, 0x05, 0x00 );
      send( socket:socudp161, data:req );

      result = recv( socket:socudp161, length:1000, timeout:1 );
      if( result ) {
        flag++;
        data += string("SNMP version",ver[i],"\n");
      }
    }

    if( flag > 0 ) {
      log_message( port:port, data:data, protocol:"udp" );
      register_service( port:port, ipproto:"udp", proto:"snmp" );
      replace_kb_item( name:"SNMP/running", value:TRUE );
    }
  } # end if (socudp161)

  port = 162;
  socudp162 = open_sock_udp( port );
  if( socudp162 ) {
    send( socket:socudp162, data:string( "\r\n" ) );
    result = recv( socket:socudp162, length:1, timeout:1 );
    if( strlen( result ) > 1 ) {
      data = "SNMP Trap Agent port open, it is possible to overflow the SNMP Traps log with fake traps (if proper community names are known), causing a Denial of Service";
      log_message( port:port, data:data, protocol:"udp" );
    }
  }
  close( socudp162 );
}

exit( 0 );
