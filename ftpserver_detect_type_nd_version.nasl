###############################################################################
# OpenVAS Vulnerability Test
# $Id: ftpserver_detect_type_nd_version.nasl 4780 2016-12-16 08:45:05Z cfi $
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
  script_version("$Revision: 4780 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-16 09:45:05 +0100 (Fri, 16 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("FTP Banner Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Product detection");
  script_require_ports("Services/ftp", 21);
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "ftpd_no_cmd.nasl");

  script_tag(name:"summary", value:"This Plugin detects the FTP Server Banner and the Banner
  of the 'HELP' command.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

port = get_ftp_port( default:21 );

banner = get_ftp_banner( port:port );

if( banner ) {

  install = port + '/tcp';

  if( "NcFTPd" >< banner ) {
    set_kb_item( name:"ftp/ncftpd", value:TRUE );
    register_product( cpe:'cpe:/a:ncftpd:ftp_server', location:install, port:port );
  }

  if( egrep( pattern:".*icrosoft FTP.*", string:banner ) ) {
    set_kb_item( name:"ftp/msftpd", value:TRUE );
    register_product( cpe:'cpe:/a:microsoft:ftp_service', location:install, port:port );
  }

  if( egrep( pattern:".*heck Point Firewall-1 Secure FTP.*", string:banner ) ) {
    set_kb_item( name:"ftp/fw1ftpd", value:TRUE );
    register_product( cpe:'cpe:/a:checkpoint:firewall-1', location:install, port:port );
  }

  if( egrep( pattern:".*Version wu-.*", string:banner ) ) {
    set_kb_item( name:"ftp/wuftpd", value:TRUE );
    register_product( cpe:'cpe:/a:wu-ftpd:wu-ftpd', location:install, port:port );
  }

  if( egrep( pattern:".*xWorks.*", string:banner ) ) {
    set_kb_item( name:"ftp/vxftpd", value:TRUE );
    register_product( cpe:'cpe:/o:windriver:vxworks', location:install, port:port );
  }

  data = 'Remote FTP server banner :\n' + banner;
  log_message( port:port, data:data );
}

exit( 0 );
