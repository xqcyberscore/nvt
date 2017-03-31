###############################################################################
# OpenVAS Vulnerability Test
# $Id: httpdx_38242.nasl 5388 2017-02-21 15:13:30Z teissa $
#
# httpdx 'MKD' Command Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
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
  script_oid("1.3.6.1.4.1.25623.1.0.100496");
  script_version("$Revision: 5388 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 16:13:30 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-02-17 20:53:20 +0100 (Wed, 17 Feb 2010)");
  script_bugtraq_id(38242);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("httpdx 'MKD' Command Directory Traversal Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38242");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/httpdx/");

  script_tag(name:"summary", value:"The 'httpdx' program is prone to a directory-traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");
  script_tag(name:"impact", value:"Exploiting this issue allows an authenticated user to create
  directories outside the FTP root directory, which may lead to other attacks.");
  script_tag(name:"affected", value:"This issue affects httpdx 1.5; other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_ftp_port( default:21 );
if( ! banner = get_ftp_banner( port:port ) ) exit( 0 );

if( "httpdx" >!< banner ) exit( 0 );

version = eregmatch( pattern:"httpdx/([0-9.]+)", string:banner );

if( ! isnull( version[1] ) ) {
  if(version_is_equal( version:version[1], test_version: "1.5" ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
