###############################################################################
# OpenVAS Vulnerability Test
# $Id: TYPSoft_ftp_server_34901.nasl 5220 2017-02-07 11:42:33Z teissa $
#
# TYPSoft FTP Server 'ABORT' Command Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100198");
  script_version("$Revision: 5220 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-07 12:42:33 +0100 (Tue, 07 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-05-12 22:04:51 +0200 (Tue, 12 May 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1668");
  script_bugtraq_id(34901);
  script_name("TYPSoft FTP Server 'ABORT' Command Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34901");

  script_tag(name:"summary", value:"TYPSoft FTP Server is prone to a remote denial-of-service
  vulnerability.");
  script_tag(name:"impact", value:"This issue allows remote attackers to cause the affected server to
  stop responding, denying service to legitimate users.");
  script_tag(name:"affected", value:"TYPSoft FTP Server 1.11 is vulnerable; other versions may also be
  affected.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_ftp_port( default:21 );
if( ! banner = get_ftp_banner( port:port ) ) exit( 0 );

if( "TYPSoft FTP Server" >!< banner ) exit( 0 );

version = eregmatch( pattern:"TYPSoft FTP Server ([0-9.]+)", string:banner );

if( ! isnull( version[1] ) ) {
  if( version_is_less_equal( version:version[1], test_version:"1.11" ) ) {
    security_message( port:port );
    exit( 0 );
  }
}  

exit( 99 );
