# OpenVAS Vulnerability Test
# $Id: ws4e_too_long_url.nasl 6540 2017-07-05 12:42:02Z cfischer $
# Description: Webserver4everyone too long URL
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

tag_summary = "It may be possible to make Webserver4everyone execute
arbitrary code by sending it a too long url with 
the Host: field set to 127.0.0.1";

tag_solution = "Upgrade your web server.";

# Some vulnerable servers:
# WebServer 4 Everyone v1.28
#
# References:
# From:"Tamer Sahin" <ts@securityoffice.net>
# To:bugtraq@securityfocus.com
# Subject: [SecurityOffice] Web Server 4 Everyone v1.28 Host Field Denial of Service Vulnerability

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11167");
  script_version("$Revision: 6540 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-05 14:42:02 +0200 (Wed, 05 Jul 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5967);
  script_cve_id("CVE-2002-1212");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Webserver4everyone too long URL");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("W4E/banner");
  script_exclude_keys("www/too_long_url_crash");

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner"); # mixed

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if(safe_checks())
{ 
  b = get_http_banner(port: port);
  if (egrep(string: b, pattern: "WebServer 4 Everyone/1\.([01][0-9]?|2[0-8])"))
    security_message(port);
  exit(0);
}

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

req = string("GET /", crap(2000), " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
send(socket:soc, data:req);
http_close_socket(soc);

if(http_is_dead(port: port))
{
  security_message(port);
  set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
