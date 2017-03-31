###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CompleteFTP_39802.nasl 5306 2017-02-16 09:00:16Z teissa $
#
# CompleteFTP Directory Traversal Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100615");
  script_version("$Revision: 5306 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-16 10:00:16 +0100 (Thu, 16 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-04-30 13:41:49 +0200 (Fri, 30 Apr 2010)");
  script_bugtraq_id(39802);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CompleteFTP Directory Traversal Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39802");
  script_xref(name:"URL", value:"http://www.enterprisedt.com/products/completeftp/");

  script_tag(name:"summary", value:"CompleteFTP is prone to a directory-traversal vulnerability because it
  fails to sufficiently sanitize user-supplied input.");
  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to download arbitrary
  files outside of the FTP server root directory. This may aid in further attacks.");
  script_tag(name:"affected", value:"CompleteFTP 3.3.0 is vulnerable; other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_ftp_port( default:21 );
if( ! banner = get_ftp_banner( port:port ) ) exit( 0 );

if( "220-Complete FTP server" >!< banner ) exit( 0 );

version = eregmatch( pattern:"220 FTP Server v ([0-9.]+)", string:banner );

if( ! isnull( version[1] ) ) {
  if( version_is_equal( version:version[1], test_version:"3.3.0" ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
