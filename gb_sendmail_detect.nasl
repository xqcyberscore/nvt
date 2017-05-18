###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sendmail_detect.nasl 5888 2017-04-07 09:01:53Z teissa $
#
# Sendmail Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800608");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 5888 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-07 11:01:53 +0200 (Fri, 07 Apr 2017) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sendmail Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"summary", value:"The script will detects the installed version of Sendmail and sets
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smtp_func.inc");

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

  if( "Sendmail" >< banner || ( ( "This is sendmail version" >< help || "sendmail-bugs@sendmail.org" >< help || "HELP not implemented" >< help || "Syntax Error, command unrecognized" >< help ) &&
      "OK" >< noop && ( "Reset state" >< rset || "OK" >< rset ) && ( "closing connection" >< quit || "Closing connection" >< quit ) ) ) {

    version = "unknown";

    vers = eregmatch( pattern:"ESMTP Sendmail ([0-9.]+)", string:banner );
    if( vers[1] ) {
      version = vers[1];
    } else {
      vers = eregmatch( pattern:"This is sendmail version ([0-9.]+)", string:help );
      if( vers[1] ) {
        version = vers[1];
      } else {
        vers = eregmatch( pattern:"Sendmail ([0-9.]+)", string:help );
        if( vers[1] ) version = vers[1];
      }
    }

    set_kb_item( name:"SMTP/sendmail", value:TRUE );
    set_kb_item( name:"SMTP/" + port + "/Sendmail", value:version );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sendmail:sendmail:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:sendmail:sendmail';

    register_product( cpe:cpe, location:port + '/tcp', port:port, service:"smtp" );

    log_message( data: build_detection_report( app:"Sendmail",
                                               version:version,
                                               install:port + '/tcp',
                                               cpe:cpe,
                                               concluded:vers[0] ),
                                               port:port );

  }
}
