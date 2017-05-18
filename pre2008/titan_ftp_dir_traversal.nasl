###############################################################################
# OpenVAS Vulnerability Test
# $Id: titan_ftp_dir_traversal.nasl 6063 2017-05-03 09:03:05Z teissa $
#
# Titan FTP Server directory traversal
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

# Ref: D4rkGr3y

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14659");
  script_version("$Revision: 6063 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(7718);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Titan FTP Server directory traversal");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"summary", value:"The remote host is running Titan FTP Server.  All versions up to and
  including 2.02 are reported vulnerable to directory traversal flaw.");
  script_tag(name:"impact", value:"An attacker could send specially crafted URL to view arbitrary files on the
  system.");
  script_tag(name:"solution", value:"Upgrade to latest version");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include ("ftp_func.inc");

port = get_ftp_port( default:21 );
if( ! banner = get_ftp_banner( port:port ) ) exit( 0 );

if( "Titan FTP Server" >!< banner ) exit( 0 );

if( egrep( pattern:"^220.*Titan FTP Server ([0-1]\.|2\.0[12][^0-9])", string:banner ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
