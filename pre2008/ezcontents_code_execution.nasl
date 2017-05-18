###############################################################################
# OpenVAS Vulnerability Test
# $Id: ezcontents_code_execution.nasl 6046 2017-04-28 09:02:54Z teissa $
#
# Remote Code Execution in ezContents
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

# From: Zero_X www.lobnan.de Team [zero-x@linuxmail.org]
# Subject: Remote Code Execution in ezContents
# Date: Saturday 10/01/2004 19:14

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12021");
  script_version("$Revision: 6046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0070");
  script_bugtraq_id(9396);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Remote Code Execution in ezContents");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"ezContents is an Open-Source website content management system based
  on PHP and MySQL. Features include maintaining menus and sub-menus, adding authors that write contents,
  permissions, workflow, and layout possibilities for the entire look of the site by simple use of settings.

  The product has been found to contain a vulnerability that would allow a remote attacker to cause the PHP
  script to include an external PHP file and execute its content. This would allow an attacker to cause
  the server to execute arbitrary code.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/module.php?link=http://xxxx./index.php";

  if( http_vuln_check( port:port, url:url, pattern:"main.*'http://xxxx\./index\.php'.*modules\.php" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );