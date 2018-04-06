###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_booking_calendar_51119.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# PHP Booking Calendar 'page_info_message' Parameter Cross Site Scripting Vulnerability
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

tag_summary = "PHP Booking Calendar is prone to a cross-site scripting vulnerability
because it fails to sufficiently sanitize user-supplied data.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

PHP Booking Calendar 10e is vulnerable; other versions may also
be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103376");
 script_bugtraq_id(51119);
 script_cve_id("CVE-2011-5045");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_version ("$Revision: 9352 $");
 script_name("PHP Booking Calendar 'page_info_message' Parameter Cross Site Scripting Vulnerability");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51119");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/bookingcalendar/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520929");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-01-04 15:47:28 +0100 (Wed, 04 Jan 2012)");
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
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/booking_calendar/", "/cal", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/details_view.php?event_id=1&date=2000-12-01&view=month&loc=loc1&page_info_message=<script>alert(/openvas-xss-test/)</script>";

  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/openvas-xss-test/\)</script>", check_header:TRUE, extra_check:"Booking Calendar" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
