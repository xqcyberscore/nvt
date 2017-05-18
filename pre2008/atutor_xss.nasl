###############################################################################
# OpenVAS Vulnerability Test
# $Id: atutor_xss.nasl 6046 2017-04-28 09:02:54Z teissa $
#
# ATutor Cross Site Scripting Vulnerability
#
# Authors:
# Josh Zlatin-Amishav <josh at ramat doti cc>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19587");
  script_version("$Revision: 6046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2649");
  script_bugtraq_id(14598);
  script_xref(name:"OSVDB", value:"18842");
  script_xref(name:"OSVDB", value:"18843");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ATutor Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2005-08/0261.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0600.html");

  tag_summary = "The remote web server contains a PHP script which is vulnerable to a
  cross site scripting issue.

  Description :

  The remote host is running ATutor, a CMS written in PHP.

  The remote version of this software is prone to cross-site scripting
  attacks due to its failure to sanitize user-supplied input.";

  tag_solution = "Unknown at this time.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

# A simple alert.
xss = "<script>alert(" + SCRIPT_NAME + ")</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode( str:xss );

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

if( get_kb_item( "www/" + port + "/generic_xss" ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/login.php?", 'course=">', exss );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "HTTP/1\.. 200" && xss >< res &&
      egrep( string:res, pattern:"Web site engine's code is copyright .+ href=.http://www\.atutor\.ca" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
