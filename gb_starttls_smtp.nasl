###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_smtp.nasl 8937 2018-02-23 11:25:34Z cfischer $
#
# SMTP STARTTLS Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103118");
  script_version("$Revision: 8937 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-23 12:25:34 +0100 (Fri, 23 Feb 2018) $");
  script_tag(name:"creation_date", value:"2011-03-11 13:29:22 +0100 (Fri, 11 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SMTP STARTTLS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service_3digits.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25, 587);

  script_tag(name:"summary", value:"Check if the remote Mailserver supports the STARTTLS command.");

  script_tag(name:"qod_type", value:"remote_banner");

 exit(0);
}

include("smtp_func.inc");

port = get_smtp_port( default:25 );

if( get_port_transport( port ) > ENCAPS_IP ) exit( 0 );

if( ! soc = smtp_open_ehlo( port:port, helo:this_host() ) ) exit( 0 );

send( socket:soc, data:string( "STARTTLS\r\n" ) );
if( ! r = smtp_recv_line( socket:soc ) ) exit( 0 );

smtp_close( socket:soc );

if( "220" >< r ) {
  set_kb_item( name:"SMTP/STARTTLS/supported", value:TRUE );
  set_kb_item( name:"smtp/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"smtp" );
  log_message( port:port, data:"The remote Mailserver supports the STARTTLS command." );
  exit(0);
} else {
  set_kb_item( name:"SMTP/STARTTLS/not_supported", value:TRUE );
  set_kb_item( name:"SMTP/STARTTLS/not_supported/port", value:port) ;
  exit( 0 );
}
