###############################################################################
# OpenVAS Vulnerability Test
# $Id: calendar_express_flaws.nasl 10862 2018-08-09 14:51:58Z cfischer $
#
# Calendar Express Multiple Flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

#  Ref: aLMaSTeR HacKeR

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.19749");
 script_version("$Revision: 10862 $");
 script_tag(name:"last_modification", value:"$Date: 2018-08-09 16:51:58 +0200 (Thu, 09 Aug 2018) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2007-3627");
 script_bugtraq_id(14504, 14505);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Calendar Express Multiple Flaws");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name:"solution", value:"Upgrade to the latest version of this software.");
 script_tag(name:"summary", value:"The remote web server contains a PHP script which is vulnerable to a cross
site scripting and SQL injection vulnerability.

Description :

The remote host is using Calendar Express, a PHP web calendar.

A vulnerability exists in this version which may allow an attacker to
execute arbitrary HTML and script code in the context of the user's browser,
and SQL injection.

An attacker may exploit these flaws to use the remote host to perform attacks
against third-party users, or to execute arbitrary SQL statements on the remote
SQL database.");

 script_tag(name:"solution_type", value:"VendorFix");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

host = http_host_name( dont_add_port:TRUE );
if( get_http_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list_unique( "/calendarexpress", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/search.php?allwords=<br><script>foo</script>&cid=0&title=1&desc=1");
  req = http_get(item:url, port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( isnull( r ) ) continue;

  if (r =~ "^HTTP/1\.[01] 200" &&  "<script>foo</script>" >< r && egrep(string:r, pattern:"Calendar Express [0-9].+ \[Powered by Phplite\.com\]") ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );