###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_prosafe_snmp_detect.nasl 7236 2017-09-22 14:59:19Z cfischer $
#
# NETGEAR ProSafe Devices Detection (SNMP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108163");
  script_version("$Revision: 7236 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-22 16:59:19 +0200 (Fri, 22 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-05-18 10:24:16 +0200 (Thu, 18 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NETGEAR ProSafe Devices Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"Detection of NETGEAR ProSafe devices.

  This script performs SNMP based detection of NETGEAR ProSafe devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if( "ProSafe" >< sysdesc ) {

  model   = "unknown";
  version = "unknown";
  build   = "unknown";
  hwapp   = "NETGRAR Prosafe";
  osapp   = "NETGEAR Prosafe Firmware";

  # Netgear ProSafe VPN Firewall FVS318v3
  if( "Netgear ProSafe VPN Firewall" >< sysdesc ) {
    pattern = "^Netgear ProSafe VPN Firewall ([0-9a-zA-Z\-]+)";
    hwapp = "NETGRAR Prosafe VPN Firewall";

  # ProSafe 802.11b/g Wireless Access Point -WG102 V5.2.8
  } else if( "ProSafe 802.11b/g Wireless Access Point" >< sysdesc ) {
    pattern = "^ProSafe 802.11b/g Wireless Access Point -([0-9a-zA-Z\-]+)";
    hwapp = "NETGRAR ProSafe 802.11b/g Wireless Access Point";

  } else {
    # GS748Tv5 ProSafe 48-port Gigabit Ethernet Smart Switch, 6.3.1.11, B1.0.0.4
    # M4100-26G ProSafe 24-port Gigabit L2+ Intelligent Edge Managed Switch, 10.0.1.16, B1.0.0.9
    # GSM7224V2 - ProSafe 24G
    pattern = "^([0-9a-zA-Z\-]+) (\- )?ProSafe";
  }

  mod = eregmatch( pattern:pattern, string:sysdesc );
  if( ! isnull( mod[1] ) ) {
    model = mod[1];
    set_kb_item( name:"netgear/prosafe/model", value:model );
    hwapp += " " + model;
  }

  vers = eregmatch( pattern:", ([0-9.]+), B", string:sysdesc );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name:"netgear/prosafe/version", value:version );
  }

  _build = eregmatch( pattern:", ([0-9.]+), B([0-9.]+)", string:sysdesc );
  if( ! isnull( _build[2] ) ) {
    build = _build[2];
    set_kb_item( name:"netgear/prosafe/build", value:build );
  }

  replace_kb_item( name:"netgear/prosafe/detected", value:TRUE );

  oscpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/o:netgear:prosafe_firmware:" );
  if( ! oscpe )
    oscpe = "cpe:/o:netgear:prosafe_firmware";

  hwcpe = "cpe:/h:netgear:" + tolower( model );

  register_product( cpe:oscpe, port:port, location:port + "/udp", service:"snmp", proto:"udp" );
  register_product( cpe:hwcpe, port:port, location:port + "/udp", service:"snmp", proto:"udp" );

  set_kb_item( name:"Host/OS/SNMP", value:"NETGEAR Prosafe Firmware" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  register_and_report_os( os:osapp, cpe:oscpe, banner_type:"SNMP sysdesc", proto:"udp", banner:sysdesc, desc:"NETGEAR ProSafe Devices Detection (SNMP)", runs_key:"unixoide" );

  report = build_detection_report( app:osapp,
                                   version:version,
                                   install:port + "/udp",
                                   cpe:oscpe,
                                   concluded:sysdesc ) + '\n';

  report += build_detection_report( app:hwapp,
                                    install:port + "/udp",
                                    cpe:hwcpe,
                                    concluded:sysdesc );

  log_message( data:report, port:port, proto:"udp" );
  exit( 0 );
}

exit( 0 );
