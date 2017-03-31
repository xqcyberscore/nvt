###############################################################################
# OpenVAS Vulnerability Test
# $Id: artmedic_links5_file_inclusion.nasl 3613 2016-06-28 17:30:00Z cfi $
#
# artmedic_links5 File Inclusion Vulnerability
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# From: Adam n30n Simuntis <n30n@satfilm.net.pl>
# Subject: artmedic_links5 PHP Script (include path) vuln
# Date: 25.6.2004 19:51

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12289");
  script_version("$Revision: 3613 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-28 19:30:00 +0200 (Tue, 28 Jun 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("artmedic_links5 File Inclusion Vulnerability");
  script_summary("Checks for artmedic_links5's PHP inclusion vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"The file inclusion vulnerability allows a remote attacker to include
  external PHP files as if they were the server's own, this causing the product to execute arbitrary code");
  script_tag(name:"summary", value:"Artmedic Links a links generating PHP script,
  has been found to contain an external file inclusion vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/artmedic_links5/index.php?id=index.php";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  if( buf =~ "HTTP/1\.. 200" && 'require("linksscript/include.php");' >< buf ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, date:report );
    exit( 0 );
  }
}

exit( 99 );
