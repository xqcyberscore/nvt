# OpenVAS Vulnerability Test
# $Id: zope_path_disclosure.nasl 14336 2019-03-19 14:53:10Z mmartin $
# Description: Zope Installation Path Disclosure
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

# http://collector.zope.org/Zope/359

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11234");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5806);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Zope Installation Path Disclosure");


  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");

  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/zope");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Zope 2.5.1b1 / 2.6.0b1 or later.");
  script_tag(name:"summary", value:"The remote web server contains an application server that is prone to
information disclosure.

Description :

There is a minor security problem in all releases of Zope prior to
version 2.5.1b1 - they reveal the installation path when an invalid
XML RPC request is sent.");
  script_xref(name:"URL", value:"http://collector.zope.org/Zope/359");
  exit(0);
}

include("http_func.inc");
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

s = http_open_socket(port);
if (! s) exit(0);

# The proof of concept request was:
# POST /Documentation/comp_tut HTTP/1.0
# Host: localhost
# Content-Type: text/xml
# Content-length: 93
#
# <?xml version="1.0"?>
# <methodCall>
# <methodName>objectIds</methodName>
# <params/>
# </methodCall>
#
# but it does not seem to be necessary IIRC.

req = http_post(port: port, item: "/Foo/Bar/OpenVAS");
send(socket: s, data: req);
a = http_recv(socket: s);
if (egrep(string: a,
         pattern: "(File|Bobo-Exception-File:) +(/[^/]*)*/[^/]+.py"))
  security_message(port);
http_close_socket(s);
