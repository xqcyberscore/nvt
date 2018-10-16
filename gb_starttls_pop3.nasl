###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_pop3.nasl 11915 2018-10-16 08:05:09Z cfischer $
#
# SSL/TLS: POP3 'STLS' Command Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105008");
  script_version("$Revision: 11915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 10:05:09 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-09 16:29:22 +0100 (Wed, 09 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: POP3 'STLS' Command Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/pop3", 110);

  script_tag(name:"summary", value:"Checks if the remote POP3 server supports SSL/TLS with the 'STLS' command.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc2595");

  exit(0);
}

include("pop3_func.inc");

port = get_pop3_port( default:110 );

if( get_port_transport( port ) > ENCAPS_IP ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

banner = recv_line( socket:soc, length:2048 );
if( ! banner ) {
  close( soc );
  exit( 0 );
}

send( socket:soc, data:'STLS\r\n' );
while( buf = recv_line( socket:soc, length:2048 ) ) {

  if( eregmatch( pattern:'^\\+OK', string:buf ) ) {
    set_kb_item( name:"pop3/" + port + "/starttls", value:TRUE );
    set_kb_item( name:"starttls_typ/" + port, value:"pop3" );
    log_message( port:port, data:"The remote POP3 server supports SSL/TLS with the 'STLS' command." );
    close( soc );
    exit( 0 );
  }
}

close( soc );
exit( 0 );