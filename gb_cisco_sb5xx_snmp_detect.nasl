###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_sb5xx_snmp_detect.nasl 7383 2017-10-09 09:19:26Z santu $
#
# Cisco Small Business 500 Series Stackable Managed Switches SNMP Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812003");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version ("$Revision: 7383 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-09 11:19:26 +0200 (Mon, 09 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-03 16:38:14 +0530 (Tue, 03 Oct 2017)");
  script_name('Cisco Small Business 500 Series Stackable Managed Switches SNMP Detection');

  script_tag(name :"summary", value :"This script performs SNMP based detection of
  Cisco Small Business 500 Series Stackable Managed Switches.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");
  exit(0);
}


include("dump.inc");
include("host_details.inc");
include("snmp_func.inc");
include("cpe.inc");

##Variable Initialization
cisPort = "";
sysdesc = "";
mod = "";
model = "";

##Parsing Function
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

##Get port
if(!cisPort = get_snmp_port(default:161)){
  exit(0);
}

##Get SNMP description
if(!sysdesc = get_snmp_sysdesc(port:cisPort)){
  exit(0);
}

##Confirm Product
##SG500-52 52-Port Gigabit Stackable Managed Switch
if(sysdesc !~ '^S(G|F)5[0-9]+.*Stackable Managed Switch$'){
  exit(0);
}

## Set KB for detection
set_kb_item( name:'cisco/500_series_stackable_managed_switch/detected', value:TRUE );

##Get Model
mod = eregmatch( pattern:'^(S[GF]5[^ ]+)', string:sysdesc );
if(mod[1])
{
  model = mod[1];
  set_kb_item( name:'cisco/500_series_stackable_managed_switch/model', value:model);
}

##Get Version
community = snmp_get_community(port:cisPort);
if(!community){
  community = "public";
}

SNMP_BASE = 42;
COMMUNITY_SIZE = strlen(community);
sz = COMMUNITY_SIZE % 256;

len = SNMP_BASE + COMMUNITY_SIZE;

for( i=1; i < 3; i++ )
{
  soc = open_sock_udp(cisPort);
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
    set_kb_item( name:'cisco/500_series_stackable_managed_switch/version', value:vers );
    cpe += ':' + vers;
    version = vers;
    break;
  }
}

if(!version) {
  version = "Unknown";
}

## build cpe and store it as host_detail
cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/o:cisco:500_series_stackable_managed_switch_firmware:");
if(isnull(cpe)){
  cpe = "cpe:/o:cisco:500_series_stackable_managed_switch_firmware";
}

register_product(cpe:cpe, location:cisPort + "/udp", service:"snmp", proto:"udp", port:cisPort);

log_message(data: build_detection_report(app:"Cisco Small Business 500 Series Stackable Managed Switch",
                                         version: version,
                                         install:cisPort + '/udp',
                                         cpe:cpe,
                                         concluded: 'The remote Host is a Cisco Small Business 500 Series Stackable Managed Switch with version ' + version),
                                         proto:"udp",
                                         port:cisPort);
exit(0);
