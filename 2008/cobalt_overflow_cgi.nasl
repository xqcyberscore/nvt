# OpenVAS Vulnerability Test
# $Id: cobalt_overflow_cgi.nasl 10033 2018-05-31 07:51:19Z ckuersteiner $
# Description: overflow.cgi detection
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Renaud Deraison
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

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.80051");
 script_version("$Revision: 10033 $");
 script_tag(name:"last_modification", value:"$Date: 2018-05-31 09:51:19 +0200 (Thu, 31 May 2018) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 script_name("overflow.cgi detection");

 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2002 Renaud Deraison");
 script_family("Web application abuses");
 script_dependencies("find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 81, 444);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name: "solution", value: "get a newer software from Cobalt");

 script_tag(name: "summary", value: "/cgi-bin/.cobalt/overflow/overflow.cgi was detected.

Some versions of this CGI allow remote users to execute arbitrary commands with the privileges of the web server.

*** OpenVAS just checked the presence of this file
*** but did not try to exploit the flaw, so this might
*** be a false positive
  
See: http://www.cert.org/advisories/CA-2002-35.html");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"/cgi-bin/.cobalt/overflow/overflow.cgi", port:port);
if(res) security_message(port);
