###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SmallFTPD_40180.nasl 5373 2017-02-20 16:27:48Z teissa $
#
# SmallFTPD 'DELE' Command Remote Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100642");
  script_version("$Revision: 5373 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:27:48 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-05-17 12:46:01 +0200 (Mon, 17 May 2010)");
  script_bugtraq_id(40180);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SmallFTPD 'DELE' Command Remote Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40180");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/smallftpd/");

  script_tag(name:"summary", value:"SmallFTPD is prone to a remote denial-of-service vulnerability.");
  script_tag(name:"impact", value:"Successful attacks will cause the application to crash, creating a denial-of-
  service condition.");
  script_tag(name:"affected", value:"SmallFTPD 1.0.3 is vulnerable; other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

port = get_ftp_port( default:21 );
if( ! banner = get_ftp_banner( port:port ) ) exit( 0 );

if( "smallftpd" >!< banner ) exit( 0 );

version = eregmatch( pattern:"smallftpd ([0-9.]+)", string:banner );

if( ! isnull( version[1] ) ) {
  if( version_is_less_equal( version:version[1], test_version:"1.0.3" ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
