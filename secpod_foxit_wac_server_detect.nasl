###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_foxit_wac_server_detect.nasl 8137 2017-12-15 11:26:42Z cfischer $
#
# Foxit WAC Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900923");
  script_version("$Revision: 8137 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 12:26:42 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Foxit WAC Server Version Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_dependencies("telnet.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ssh", 22, "Services/telnet", 23);

  script_tag(name:"summary", value:"This script finds the version of Foxit WAC Server and
  saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sshdPorts = get_kb_list( "Services/ssh" );
if( ! sshdPorts ) sshdPorts = make_list( 22 );

telnetPorts = get_kb_list( "Services/telnet" );
if( ! telnetPorts ) telnetPorts = make_list( 23 );

foreach port( make_list( sshdPorts, telnetPorts ) ) {

  if( ! get_port_state( port ) ) continue;

  # SSH-1.99-Foxit-WAC-Server-2.0 Build 3503
  # Welcome to WAC Server 2.0 Build 3503. (C) Foxit Software, 2002-2003
  banner = get_kb_item( "SSH/banner/" + port );
  if( "Foxit-WAC-Server" >!< banner ) {
    banner = get_kb_item( "telnet/banner/" + port );
    if( "WAC" >!< banner || "Foxit Software" >!< banner ) continue;
  }

  version = "unknown";

  vers = eregmatch( pattern:"(Foxit-WAC-Server-|WAC Server )(([0-9.]+).?(([a-zA-Z]+[ 0-9]+))?)", string:banner );
  if( ! isnull( vers[2] ) ) {
    version = ereg_replace( pattern:" ", string:vers[2], replace:"." );
    version = ereg_replace( pattern:"\.Build", string:version, replace:"" );
  }
   
  set_kb_item( name:"Foxit-WAC-Server/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:wac_server:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:foxitsoftware:wac_server";

  register_product( cpe:cpe, location:port + '/tcp', port:port );

  log_message( data:build_detection_report( app:"Foxit WAC Server",
                                                version:version,
                                                install:port + '/tcp',
                                                cpe:cpe,
                                                concluded:vers[0] ),
                                                port:port );
}

exit( 0 );