###############################################################################
# OpenVAS Vulnerability Test
# $Id: b2evolution_net_sql_injection.nasl 6046 2017-04-28 09:02:54Z teissa $
#
# b2Evolution title SQL Injection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# b2Evolution Security Flaws - SQL Injection - Forgot to incldue a solution.
# From: r0ut3r <shady.underground@gmail.com>
# Date: 2005-01-06 10:05

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16121");
  script_version("$Revision: 6046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(12179);
  script_name("b2Evolution title SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/13718");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1012797");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/18762");

  script_tag(name:"solution", value:"None at this time");
  script_tag(name:"summary", value:"The remote host is running b2evolution, a blog engine written in PHP.

  There is an SQL injection vulnerability in the remote version of this software which may
  allow an attacker to execute arbitrary SQL statements against the remote database by providing
  a malformed value to the 'title' argument of index.php.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php?blog=1&title='&more=1&c=1&tb=1&pb=1";

  if( http_vuln_check( port:port, url:url, pattern:"SELECT DISTINCT ID, post_author, post_issue_date" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
