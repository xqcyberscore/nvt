###############################################################################
# OpenVAS Vulnerability Test
# $Id: ftpserver_detect_type_nd_version.nasl 9541 2018-04-19 13:42:33Z cfischer $
#
# FTP Banner Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10092");
  script_version("$Revision: 9541 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-19 15:42:33 +0200 (Thu, 19 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("FTP Banner Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Product detection");
  # get_ftp_banner() is using a FTP command internally which requires a
  # successful login so the secpod_ftp_anonymous.nasl is expected to be
  # in here. This dependency also pulls in the logins.nasl.
  script_dependencies("find_service2.nasl", "find_service_3digits.nasl",
                      "ftpd_no_cmd.nasl", "secpod_ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"summary", value:"This Plugin detects and reports a FTP Server Banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

port   = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );

# Basic sanity check, we should have at least three digits for a FTP service
if( banner && strlen( banner ) > 2 ) {

  set_kb_item( name:"ftp_banner/available", value:TRUE );
  install = port + '/tcp';

  if( "NcFTPd" >< banner ) {
    set_kb_item( name:"ftp/ncftpd", value:TRUE );
    register_product( cpe:'cpe:/a:ncftpd:ftp_server', location:install, port:port );
  }

  if( "FtpXQ FTP" >< banner ) {
    set_kb_item( name:"ftp/ftpxq", value:TRUE );
  }

  if( egrep( pattern:".*heck Point Firewall-1 Secure FTP.*", string:banner ) ) {
    set_kb_item( name:"ftp/fw1ftpd", value:TRUE );
    register_product( cpe:'cpe:/a:checkpoint:firewall-1', location:install, port:port );
  }

  # 220 VxWorks FTP server (VxWorks 5.3.1 - Secure NetLinx version (1.0)) ready.
  # 220 VxWorks (VxWorks5.4.2) FTP server ready
  # 220 VxWorks (5.4) FTP server ready
  # 220 VxWorks FTP server (VxWorks VxWorks5.5.1) ready.
  # 220 Tornado-vxWorks (VxWorks5.5.1) FTP server ready
  # 220 $hostname FTP server (VxWorks 6.4) ready.
  # 220 VxWorks (VxWorks 6.3) FTP server ready
  # 220 Tornado-vxWorks FTP server ready
  # TODO: Move into own Detection-NVT. The OS part via of VxWorks is already done in gb_ftp_os_detection.nasl
  if( banner =~ "[vV]xWorks" && "FTP server" >< banner ) {
    set_kb_item( name:"ftp/vxftpd", value:TRUE );
    register_product( cpe:'cpe:/o:windriver:vxworks', location:install, port:port );
  }
  log_message( port:port, data:'Remote FTP server banner :\n' + banner );
}

exit( 0 );
