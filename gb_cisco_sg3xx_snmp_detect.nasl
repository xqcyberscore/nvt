###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_sg3xx_snmp_detect.nasl 7239 2017-09-22 16:10:31Z cfischer $
#
# Cisco Small Business 300 Series Managed Switch SNMP Detection
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
 script_oid("1.3.6.1.4.1.25623.1.0.105587");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 7239 $");
 script_tag(name:"last_modification", value:"$Date: 2017-09-22 18:10:31 +0200 (Fri, 22 Sep 2017) $");
 script_tag(name:"creation_date", value:"2013-10-14 14:24:09 +0200 (Mon, 14 Oct 2013)");
 script_name('Cisco Small Business 300 Series Managed Switch SNMP Detection');
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("gb_snmp_sysdesc.nasl");
 script_require_udp_ports("Services/udp/snmp", 161);
 script_mandatory_keys("SNMP/sysdesc/available");

 script_tag(name : "summary" , value : "This script performs SNMP based detection of Cisco Small Business 300 Series Managed Switch.");

 script_tag(name:"qod_type", value:"remote_banner");

 exit(0);
}

include("dump.inc");
include("host_details.inc");
include("snmp_func.inc");

function parse_result( data )
{
  if( strlen( data ) < 8 ) return FALSE;

  for( v=0; v < strlen( data ); v++ )
  {
    if( ord( data[v] ) == 43 && ord( data[v-1] ) == 15 )
    {
        ok = TRUE;
        break;
    }
    oid_len = ord( data[v] );
  }

  if( ! ok || oid_len < 8 ) return FALSE;

  tmp = substr( data,( v + oid_len + 2 ) );

  if( ! isprint( c:tmp[0] ) )
    tmp = substr( tmp,1,strlen( tmp ) - 1);

  return tmp;
}

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if( sysdesc !~ '^S(G|F)3[0-9]+.*Managed Switch$' ) exit(0);

cpe = 'cpe:/o:cisco:300_series_managed_switch_firmware';
version = 'unknown';

set_kb_item( name:'cisco/300_series_managed_switch/detected', value:TRUE );

mod = eregmatch( pattern:'^(S[GF]3[^ ]+)', string:sysdesc );
if( ! isnull( mod[1] ) )
{
  model = mod[1];
  set_kb_item( name:'cisco/300_series_managed_switch/model', value:model );
}

community = snmp_get_community( port:port );
if( ! community) community = "public";

SNMP_BASE = 42;
COMMUNITY_SIZE = strlen(community);
sz = COMMUNITY_SIZE % 256;

len = SNMP_BASE + COMMUNITY_SIZE;

for( i=1; i < 3; i++ )
{
  soc = open_sock_udp( port );
  if( ! soc ) continue;

  sendata = raw_string( 0x30,len,0x02,0x01,i,0x04,sz ) +
            community +
            raw_string( 0xa0,0x23,0x02,0x04,0x2b,0x8c,0x0b,0xc0,
                        0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x15,
                        0x30,0x13,0x06,0x0f,0x2b,0x06,0x01,0x02,
                        0x01,0x2f,0x01,0x01,0x01,0x01,0x0a,0xa0,
                        0x80,0x81,0x00,0x05,0x00 );

  send( socket:soc, data:sendata );
  result = recv( socket:soc, length:128, timeout:1 );

  if( ! result || ord( result[0] ) != 48 ) continue;

  vers = parse_result( data:result );
  if( vers =~ '^[0-9]+\\.' )
  {
    set_kb_item( name:'cisco/300_series_managed_switch/version', value:vers );
    cpe += ':' + vers;
    version = vers;
    break;
  }
}

register_product( cpe:cpe, location:port + "/udp", service:"snmp", proto:"udp" );

report = 'The remote Host is a Cisco Small Business 300 Series Managed Switch\n' +
         'Version: ' + version + '\n' + 
         'CPE:     ' + cpe;

if( model ) report += '\nModel:   ' + model + '\n';

log_message( port:port, proto:"udp", data:report );

exit( 0 );
