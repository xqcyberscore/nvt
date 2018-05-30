###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_buffalo_linkstation_12_12.nasl 10005 2018-05-29 13:54:41Z cfischer $
#
# Buffalo Linkstation Privilege Escalation / Information Disclosure
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
 script_oid("1.3.6.1.4.1.25623.1.0.103617");
 script_version("$Revision: 10005 $");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("Buffalo Linkstation Privilege Escalation / Information Disclosure");

 script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118532/Buffalo-Linkstation-Privilege-Escalation-Information-Disclosure.html");

 script_tag(name:"last_modification", value:"$Date: 2018-05-29 15:54:41 +0200 (Tue, 29 May 2018) $");
 script_tag(name:"creation_date", value:"2012-12-03 17:27:36 +0100 (Mon, 03 Dec 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "summary" , value : "Buffalo Linkstation suffers from information disclosure and privilege escalation vulnerabilities.");

 script_tag(name:"solution_type", value:"NoneAvailable");

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = '/cgi-bin/top.cgi';

if(http_vuln_check(port:port, url:url, pattern:"LinkStation")) {

  url = '/modules/webaxs/module/files/password';

  if(http_vuln_check(port:port, url:url,pattern:"[a-zA-Z0-9.-_]+:[[a-zA-Z0-9.$/-_]+",check_header:TRUE,extra_check:"text/plain")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
