###############################################################################
# OpenVAS Vulnerability Test
# $Id: ibproarcade_sql_injection.nasl 6056 2017-05-02 09:02:50Z teissa $
#
# IBProArcade index.php SQL Injection
#
# Authors:
# Ami Chayun
#
# Copyright:
# Copyright (C) 2004 Ami Chayun
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
  script_oid("1.3.6.1.4.1.25623.1.0.16086");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-1430");
  script_bugtraq_id(12138);
  script_name("IBProArcade index.php SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Ami Chayun");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The remote host is running ibProArcade a web based score board system written
  in PHP.

  One of the application's CGIs, index.php, is vulnerable to an SQL injection
  vulnerability in the 'gameid' parameter. An attacker may exploit this flaw to
  execute arbitrary SQL statements against the remote database.";

  tag_solution = "Upgrade to the newest version of this program";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/index.php?act=Arcade&do=stats&gameid=1'" );

  if( http_vuln_check( port:port, url:url, pattern:"SELECT COUNT\(s_id\) AS amount FROM ibf_games_scores" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
