###############################################################################
# OpenVAS Vulnerability Test
# $Id: psychostats_xss.nasl 6056 2017-05-02 09:02:50Z teissa $
#
# PsychoStats Login Parameter Cross-Site Scripting
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

# Cross Site Scripting In PsychoStats 2.2.4 Beta && Earlier
# "GulfTech Security" <security@gulftech.org>
# 2004-12-23 02:50

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16057");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2004-1417");
  script_bugtraq_id(12089);
  script_name("PsychoStats Login Parameter Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "cross_site_scripting.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the newest version of this software.");
  script_tag(name:"summary", value:"PsychoStats is a statistics generator for games. Currently there is support
  for a handful of Half-Life 'MODs' including Counter-Strike, Day of Defeat, and Natural Selection.

  There is a bug in this software which makes it vulnerable to HTML and JavaScript injection. An attacker
  may use this flaw to use the remote server to set up attacks against third-party users.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

if( get_kb_item( "www/" + port + "/generic_xss" ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/login.php?login=<script>foo</script>";

  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:'"login" value="<script>foo</script>' ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
