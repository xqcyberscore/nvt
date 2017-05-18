###############################################################################
# OpenVAS Vulnerability Test
# $Id: fishcart_sql_injection.nasl 5992 2017-04-20 14:42:07Z cfi $
#
# FishCart SQL injections
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# Multiple SQL injections and XSS in FishCart 3.1
# "Diabolic Crab" <dcrab@hackerscenter.com>
# 2005-05-03 23:07

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18191");
  script_version("$Revision: 5992 $");
  script_cve_id("CVE-2005-1486", "CVE-2005-1487");
  script_bugtraq_id(13499);
  script_tag(name:"last_modification", value:"$Date: 2017-04-20 16:42:07 +0200 (Thu, 20 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FishCart SQL injections");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"FishCart, in use since January 1998, is a proven Open Source
  e-commerce system for products, services, online payment and online donation management.
  Written in PHP4, FishCart has been tested on Windows NT, Linux, and various Unix platforms.
  FishCart presently supports the MySQL, PostgreSQL, Solid, Oracle and MSSQL.

  FishCart contains multiple SQL injection vulnerabilities in the program
  that can be exploited to modify/delete/insert entries into the database.

  In addition, the program suffers from cross site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = string( dir, "/upstnt.php?zid=1&lid=1&cartid='" );
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "Invalid SQL: select sku,qty from mwestoline where orderid='''" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
