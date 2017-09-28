###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_surveyor_xss_sql.nasl 7287 2017-09-27 06:56:51Z cfischer $
#
# Multiple vulnerabilities in PHP Surveyor
#
# Authors:
# Josh Zlatin-Amishav
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
  script_oid("1.3.6.1.4.1.25623.1.0.19494");
  script_version("$Revision: 7287 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-27 08:56:51 +0200 (Wed, 27 Sep 2017) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2380", "CVE-2005-2381", "CVE-2005-2398", "CVE-2005-2399");
  script_bugtraq_id(14329, 14331);
  script_xref(name:"OSVDB", value:"18086");
  script_xref(name:"OSVDB", value:"18087");
  script_xref(name:"OSVDB", value:"18088");
  script_xref(name:"OSVDB", value:"18089");
  script_xref(name:"OSVDB", value:"18090");
  script_xref(name:"OSVDB", value:"18091");
  script_xref(name:"OSVDB", value:"18092");
  script_xref(name:"OSVDB", value:"18093");
  script_xref(name:"OSVDB", value:"18094");
  script_xref(name:"OSVDB", value:"18095");
  script_xref(name:"OSVDB", value:"18096");
  script_xref(name:"OSVDB", value:"18097");
  script_xref(name:"OSVDB", value:"18098");
  script_xref(name:"OSVDB", value:"18099");
  script_xref(name:"OSVDB", value:"18100");
  script_xref(name:"OSVDB", value:"18101");
  script_xref(name:"OSVDB", value:"18102");
  script_xref(name:"OSVDB", value:"18103");
  script_xref(name:"OSVDB", value:"18104");
  script_xref(name:"OSVDB", value:"18105");
  script_xref(name:"OSVDB", value:"18107");
  script_xref(name:"OSVDB", value:"18108");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Multiple vulnerabilities in PHP Surveyor");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://securityfocus.com/archive/1/405735");

  tag_summary = "The remote host is running PHP Surveyor, a set of PHP scripts used to
  develop, publish and collect responses from surveys.

  The remote version of this software contains multiple vulnerabilities
  that can lead to SQL injection, path disclosure and cross-site scripting.";

  tag_solution = "Unknown at this time.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/admin/admin.php?sid='" );

  if( http_vuln_check( port:port, url:url, pattern:"<title>PHP Surveyor</title>", extra_check:"not a valid MySQL result" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
