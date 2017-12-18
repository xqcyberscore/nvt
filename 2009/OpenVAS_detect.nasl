###############################################################################
# OpenVAS Vulnerability Test
# $Id: OpenVAS_detect.nasl 8139 2017-12-15 11:57:25Z cfischer $
#
# OpenVAS Scanner Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100076");
  script_version("$Revision: 8139 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 12:57:25 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-24 18:59:36 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OpenVAS Scanner Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 9391);

  script_tag(name:"summary", value:"Detection of OpenVAS Scanner.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

port = get_unknown_port( default:9391 );

foreach protocol( make_list( "1.0", "1.1", "1.2", "2.0" ) ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  req = string( "< OTP/", protocol, " >\n" );
  send( socket:soc, data:req );
  res = recv_line( socket:soc, length:20 );
  close( soc );

  if( ereg( pattern:"^< OTP/" + protocol + " >$", string:res ) ) {

    set_kb_item( name:"openvas_scanner/installed", value:TRUE );
    set_kb_item( name:"openvas_framework_component/installed", value:TRUE );

    cpe = "cpe:/a:openvas:openvas_scanner";
    vers = "unknown";
    install = port + "/tcp";

    register_service( port:port, proto:"openvas-scanner" );
    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"OpenVAS Scanner",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:res ),
                                              port:port );
    break;
  }
}

exit( 0 );
