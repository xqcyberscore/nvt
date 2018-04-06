###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iguard_53355.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# iGuard Security Access Control Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "iGuard Security Access Control is prone to a cross-site scripting
vulnerability because it fails to properly sanitize user-supplied
input in the embedded web server.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103485");
 script_bugtraq_id(53355);
 script_version ("$Revision: 9352 $");
 script_name("iGuard Security Access Control Cross Site Scripting Vulnerability");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53355");
 script_xref(name : "URL" , value : "http://iguard.me/iguard-access-control.html");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-05-08 10:33:52 +0200 (Tue, 08 May 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.html";
  buf = http_get_cache( item:url, port:port );

  if( "Server: iGuard" >< buf || "<TITLE>iGuard Security" >< buf ) {

    url = '/%3E%3C/font%3E%3CIFRAME%20SRC=%22JAVASCRIPT:alert(%27openvas-xss-test%27);%22%3E.asp';

    if( http_vuln_check( port:port, url:url, pattern:"<IFRAME SRC=.JAVASCRIPT:alert\('openvas-xss-test'\);.>", check_header:TRUE ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
