###############################################################################
# OpenVAS Vulnerability Test
# $Id: sniff_css.nasl 6063 2017-05-03 09:03:05Z teissa $
#
# Snif Cross Site Scripting
#
# Authors:
# Noam Rathaus
# Changes by rd: description
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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

# Ref:
# From: Justin Hagstrom [justinhagstrom@yahoo.com]
# To: news@securiteam.com
# Subject: Snif Script Cross Site Scripting Vulnerability
# Date: Tuesday 09/12/2003 02:40

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11949");
  script_version("$Revision: 6063 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9179);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Snif Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"None at this time - disable this CGI suite");
  script_tag(name:"summary", value:"The remote host is running the 'Snif' CGI suite. There is a vulnerability in
  it which may allow an attacker to insert a malicious HTML and/or Javascript snipet in the response returned to
  a third party user (this problem is known as a cross site scripting bug).");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php?path=<script>malicious_code</script>";

  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<script>malicious_code</script></title>" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
