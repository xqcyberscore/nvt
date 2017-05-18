###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exim_detect.nasl 6063 2017-05-03 09:03:05Z teissa $
#
# Exim Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105189");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 6063 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
  script_tag(name:"creation_date", value:"2015-01-29 15:29:06 +0100 (Thu, 29 Jan 2015)");
  script_name("Exim Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the
  server and attempts to extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");
include("cpe.inc");

port = get_kb_item( "Services/smtp" );
if( ! port ) port = 25;
if( ! get_port_state( port ) ) port = 465;
if( ! get_port_state( port ) ) port = 587;

if( get_port_state( port ) ) {

  banner = get_smtp_banner( port:port );

  quit = get_kb_item( "smtp/" + port + "/quit" );
  noop = get_kb_item( "smtp/" + port + "/noop" );
  help = get_kb_item( "smtp/" + port + "/help" );
  rset = get_kb_item( "smtp/" + port + "/rset" );

  if( "exim" >< tolower( banner ) || ( "closing connection" >< quit &&
      "OK" >< noop && "Commands supported:" >< help && "Reset OK" >< rset ) ) {

    vers = 'unknown';
    version = eregmatch( pattern:'ESMTP Exim ([0-9.]+(_[0-9]+)?)', string:banner );
    if( version[1] ) vers = version[1];

    if( "_" >< vers )
      vers = str_replace( string:vers, find:"_", replace:".");

    set_kb_item( name:"exim/installed", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/exim", value:vers );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:exim:exim:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:exim:exim';

    register_product( cpe:cpe, location:port + "/tcp", port:port, service:"smtp" );

    log_message( data: build_detection_report( app:"Exim",
                                               version:vers,
                                               install:port + "/tcp",
                                               cpe:cpe,
                                               concluded: banner ),
                                               port:port );
  }
}

exit( 0 );
