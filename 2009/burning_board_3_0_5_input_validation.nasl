###############################################################################
# OpenVAS Vulnerability Test
# $Id: burning_board_3_0_5_input_validation.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Woltlab Burning Board Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Woltlab Burning Board is prone to multiple input-validation vulnerabilities, including:

  - Multiple security that may allow attackers to delete private messages
  - A cross-site scripting vulnerability
  - Multiple URI redirection vulnerabilities

  Attackers can exploit these issues to delete private messages,
  execute arbitrary script code, steal cookie-based authentication
  credentials and redirect users to malicious sites.

 Vulnerable:  	 
  Woltlab Burning Board 3.0.5
  Woltlab Burning Board 3.0.3 PL 1
  Woltlab Burning Board 3.0";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100056");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)");
 script_bugtraq_id(34057);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Woltlab Burning Board Multiple Input Validation Vulnerabilities");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34057");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/forum", "/board", cgi_dirs( port:port ) ) ) { 

  if( dir == "/" ) dir = "";
  url = string(dir, "/wcf/acp/dereferrer.php?url=javascript:alert(document.cookie);");
 
  if(http_vuln_check(port:port, url:url, pattern:".*<a href=.javascript:alert\(document.cookie\);.>javascript:alert\(document.cookie\);</a>.*", check_header:TRUE)) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
