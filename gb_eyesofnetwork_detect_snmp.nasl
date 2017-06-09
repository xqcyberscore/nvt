###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eyesofnetwork_detect_snmp.nasl 6189 2017-05-22 15:08:51Z cfi $
#
# Eyes Of Network (EON) Detection (SNMP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108168");
  script_version("$Revision: 6189 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-22 17:08:51 +0200 (Mon, 22 May 2017) $");
  script_tag(name:"creation_date", value:"2017-05-22 09:21:05 +0200 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Eyes Of Network (EON) Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_mandatory_keys("SNMP/sysdesc");
  script_require_udp_ports("Services/udp/snmp", 161);

  script_tag(name:"summary", value:"This script performs SNMP based detection of Eyes Of Network (EON).");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("snmp_func.inc");
include("misc_func.inc");

if( ! defined_func( "snmpv3_get" ) ) exit( 0 );

port = get_kb_item( "Services/udp/snmp" );
if( ! port ) port = 161;
if( ! get_udp_port_state( port ) ) exit( 0 );
if( ! sysdesc = get_kb_item( "SNMP/sysdesc" ) );
if( "Linux" >!< sysdesc ) exit( 0 );

# Try the installed packages to check for the eonweb package containing the version
for( i = 0; i <= 500; i++ ) {

  oid = "1.3.6.1.2.1.25.6.3.1.2." + i;

  res = snmp_get( port:port, oid:oid );
  if( res && "eonweb-" >< res && ".eon" >< res ) {

    replace_kb_item( name:"eyesofnetwork/detected", value:TRUE );
    replace_kb_item( name:"eyesofnetwork/snmp/detected", value:TRUE );
    set_kb_item( name:"eyesofnetwork/snmp/port", value:port );

    version = "unknown";

    vers = eregmatch( pattern:"eonweb-([0-9.]+)(.*)\.eon", string:res );
    if( vers[1] ) { 
      version = vers[1];
      set_kb_item( name:"eyesofnetwork/snmp/" + port + "/version", value:version );
      set_kb_item( name:"eyesofnetwork/snmp/" + port + "/concluded", value:res );
      set_kb_item( name:"eyesofnetwork/snmp/" + port + "/concludedOID", value:oid );
    }
    break;
  }
}

exit( 0 );
