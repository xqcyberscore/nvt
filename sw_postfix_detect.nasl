###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_postfix_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Postfix SMTP Server Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111086");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-04 17:00:00 +0100 (Thu, 04 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Postfix SMTP Server Detection");

  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"summary", value:"The script checks the SMTP server
  banner for the presence of Postfix.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("smtp_func.inc");
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

  if( "ESMTP Postfix" >< banner || "Ubuntu/Postfix;" >< banner ||
    ( "Bye" >< quit && "Ok" >< noop && "Error: command not recognized" >< help && "Ok" >< rset ) ) {

    version = "unknown";
    ver = eregmatch( pattern:"220.*Postfix \(([0-9\.]+)\)", string:banner );
    if( ver[1] ) version = ver[1];

    set_kb_item( name:"SMTP/postfix", value:TRUE );
    set_kb_item( name:"SMTP/" + port + "/Postfix", value:version );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:postfix:postfix:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:postfix:postfix';

    register_product( cpe:cpe, location:port + '/tcp', port:port, service:"smtp" );

    log_message( data: build_detection_report( app:"Postfix",
                                               version:version,
                                               install:port + '/tcp',
                                               cpe:cpe,
                                               concluded:banner ),
                                               port:port );
  }
}

exit( 0 );
