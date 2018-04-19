###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_vsftpd_detect.nasl 9537 2018-04-19 11:49:54Z cfischer $
#
# vsFTPd FTP Server Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111050");
  script_version("$Revision: 9537 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-19 13:49:54 +0200 (Thu, 19 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-11-11 18:00:00 +0100 (Wed, 11 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("vsFTPd FTP Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp_banner/available");

  script_tag(name:"summary", value:"The script is grabbing the
  banner of a FTP server and attempts to identify a vsFTPd FTP Server
  and its version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("cpe.inc");

port = get_ftp_port( default:21 );
if( ! banner = get_ftp_banner( port:port ) ) exit( 0 );
if( "vsftpd" >!< tolower( banner ) ) exit( 0 );

vers = "unknown";
version = eregmatch( pattern:"vsftpd ([0-9.]+)", string: tolower( banner ) );
if( ! isnull( version[1] ) ) {
  vers = version[1];
  set_kb_item( name:"ftp/" + port + "/vsftpd", value:vers );
}

set_kb_item( name:"vsftpd/installed", value:TRUE );

cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:beasts:vsftpd:" );
if( isnull( cpe ) )
  cpe = 'cpe:/a:beasts:vsftpd';

register_product( cpe:cpe, location:port + '/tcp', port:port );

log_message( data:build_detection_report( app:"vsFTPd",
                                          version:vers,
                                          install:port + '/tcp',
                                          cpe:cpe,
                                          concluded:banner ),
                                          port:port );
exit( 0 );
