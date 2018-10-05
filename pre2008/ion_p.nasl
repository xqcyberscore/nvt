###############################################################################
# OpenVAS Vulnerability Test
# $Id: ion_p.nasl 11761 2018-10-05 10:25:32Z jschulte $
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
  script_version("$Revision: 11761 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:25:32 +0200 (Fri, 05 Oct 2018) $");
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

  script_tag(name:"summary", value:"The ion-p.exe exists on this webserver.
  Some versions of this file are vulnerable to remote exploit.");
  script_tag(name:"impact", value:"An attacker, exploiting this vulnerability, may be able to gain
  access to confidential data and/or escalate their privileges on the Web server.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port( default:80 );

files = traversal_files();

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  if( host_runs( "windows" ) == "yes" ) {
    prefix = "c:\\";
  } else if( host_runs( "linux" ) == "yes" ) {
    prefix = "../../../../../";
  } else {
    # This CGI is low prio these days so don't run this test against a system we don't know the OS.
    exit(0);
  }

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    url = dir + "/ion-p.exe?page=" + prefix + file;

    if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
