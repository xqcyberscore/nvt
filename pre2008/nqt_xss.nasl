###############################################################################
# OpenVAS Vulnerability Test
# $Id: nqt_xss.nasl 6053 2017-05-01 09:02:51Z teissa $
#
# Network Query Tool XSS
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

# From: Janek Vind <come2waraxe@yahoo.com>
# Subject: [waraxe-2004-SA#024 - XSS and full path disclosure in Network Query Tool 1.6]
# Date: 2004-04-24 04:20

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12223");
  script_version("$Revision: 6053 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1964");
  script_bugtraq_id(10205);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Network Query Tool XSS");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "cross_site_scripting.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is using Network Query Tool. There is a bug in this
  software that makes it vulnerable to cross site scripting attacks.");
  script_tag(name:"impact", value:"An attacker may use this bug to steal the credentials of the legitimate
  users of this site.");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

if( get_kb_item( "www/" + port + "/generic_xss" ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/nqt", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/nqt.php?target=127.0.0.1&queryType=all&portNum=foobar%3Cscript%3Efoo%3C/script%3E";

  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<script>foo</script>" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
