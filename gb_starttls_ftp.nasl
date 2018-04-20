###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_ftp.nasl 9541 2018-04-19 13:42:33Z cfischer $
#
# FTP STARTTLS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105009");
  script_version("$Revision: 9541 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-19 15:42:33 +0200 (Thu, 19 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-04-09 16:39:22 +0100 (Wed, 09 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("FTP STARTTLS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"summary", value:"The remote FTP Server supports the STARTTLS command.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port( default:21 );

if( get_port_transport( port ) > ENCAPS_IP ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

buf = ftp_recv_line( socket:soc );
if( ! buf ) {
  close( soc );
  exit( 0 );
}

buf = ftp_send_cmd( socket:soc, cmd:'AUTH TLS\r\n' );
close( soc );

if( "234" >< buf ) {
  set_kb_item( name:"ftp/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"ftp" );
  log_message( port:port );
}

exit( 0 );
