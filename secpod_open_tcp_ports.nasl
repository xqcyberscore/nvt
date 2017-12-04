###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_open_tcp_ports.nasl 7922 2017-11-28 10:06:28Z cfischer $
#
# Checks for open TCP ports
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900239");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 7922 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-28 11:06:28 +0100 (Tue, 28 Nov 2017) $");
  script_tag(name:"creation_date", value:"2010-04-16 11:02:50 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Checks for open TCP ports");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("dont_scan_printers.nasl", "dont_print_on_printers.nasl");

  script_tag(name:"summary", value:"Collects all open TPC ports of the
  TCP ports identified so far.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_add_preference(name:"Silent", type:"checkbox", value:"yes");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

opened_tcp_ports = "";

silent = script_get_preference( "Silent" );
if( silent == 'yes' ) {
  be_silent = TRUE;
}  

## Get all TCP ports
tcp_ports = get_kb_list( "Ports/tcp/*" );

if( ! tcp_ports  ) {
  if( ! be_silent ) {
    log_message( port:0, data:"Open TCP ports: [None found]" );
  }
  exit( 0 );
}

foreach port( keys( tcp_ports ) ) {

  ## Extract port number
  Port = eregmatch( string:port, pattern:"Ports/tcp/([0-9]+)" );
  if( ! Port && ! get_port_state( Port[1] ) ) {
    continue;
  }

  # Includes e.g. PJL ports which are printing everything
  # sent to them so dont include this ports here
  if( ! is_fragile_port( port:Port[1] ) ) {
    set_kb_item( name:"TCP/PORTS", value:Port[1] );
  }

  opened_tcp_ports += Port[1] + ", ";
}

if( strlen( opened_tcp_ports ) ) {

  opened_tcp_ports = ereg_replace( string:chomp( opened_tcp_ports ), pattern:",$", replace:"" );
  opened_tcp_ports_kb = str_replace( string:opened_tcp_ports, find:" ", replace:"" );
  set_kb_item( name:"Ports/open/tcp", value:opened_tcp_ports_kb );
  register_host_detail( name:"ports", value:opened_tcp_ports_kb,
    nvt:"1.3.6.1.4.1.25623.1.0.900239", desc:"Check Open TCP Ports" );
  register_host_detail( name:"tcp_ports", value:opened_tcp_ports_kb,
    nvt:"1.3.6.1.4.1.25623.1.0.900239", desc:"Check Open TCP Ports" );

  if( be_silent ) exit( 0 );

  log_message( port:0, data:"Open TCP ports: "+ opened_tcp_ports );
} else {
  if( ! be_silent ) {
    log_message( port:0, data:"Open TCP ports: [None found]" );
  }
}

exit( 0 );
