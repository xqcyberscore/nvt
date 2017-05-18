###############################################################################
# OpenVAS Vulnerability Test
# $Id: bookreview_xss.nasl 5992 2017-04-20 14:42:07Z cfi $
#
# BookReview Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
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
  script_oid("1.3.6.1.4.1.25623.1.0.18375");
  script_version("$Revision: 5992 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-20 16:42:07 +0200 (Thu, 20 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2005-1782");
  script_bugtraq_id(13783);
  script_xref(name:"OSVDB", value:"16871");
  script_xref(name:"OSVDB", value:"16872");
  script_xref(name:"OSVDB", value:"16873");
  script_xref(name:"OSVDB", value:"16874");
  script_xref(name:"OSVDB", value:"16875");
  script_xref(name:"OSVDB", value:"16876");
  script_xref(name:"OSVDB", value:"16877");
  script_xref(name:"OSVDB", value:"16878");
  script_xref(name:"OSVDB", value:"16879");
  script_xref(name:"OSVDB", value:"16880");
  script_xref(name:"OSVDB", value:"16881");
  script_name("BookReview Multiple Cross-Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The remote web server contains a CGI which is vulnerable to multiple cross site
  scripting vulnerabilities.

  Description :

  The remote host is running the BookReview software.

  The remote version of this software is vulnerable to multiple cross-site
  scripting vulnerabilities due to a lack of sanitization of user-supplied data.

  Successful exploitation of this issue may allow an attacker to use the
  remote server to perform an attack against a third-party user.";

  tag_solution = "None at this time";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

if( get_kb_item( "www/" + port + "/generic_xss" ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/add_url.htm?node=%3Cscript%3Ealert('XSS')%3C/script%3E";

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('XSS'\)</script>", extra_check:"Powered by BookReview", check_header:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
