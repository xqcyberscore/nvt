###################################################################
# OpenVAS Vulnerability Test
# $Id: ndcgi.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# ndcgi.exe vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11730");
  script_version("$Revision: 6040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0922");
  script_bugtraq_id(3583); 
  script_name("ndcgi.exe vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"remove it from /cgi-bin.
  More info can be found at: http://marc.theaimsgroup.com/?l=bugtraq&m=100681274915525&w=2");
  script_tag(name:"summary", value:"The file ndcgi.exe exists on this webserver.  
  Some versions of this file are vulnerable to remote exploit.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

no404 = get_kb_item( "www/no404/" + port );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/ndcgi.exe";

  if( is_cgi_installed_ka( item:url, port:port ) ) {
    if( no404 && is_cgi_installed_ka( item:dir + "/openvas" + rand() + ".exe", port:port ) ) exit( 0 );
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );