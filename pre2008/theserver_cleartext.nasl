# OpenVAS Vulnerability Test
# $Id: theserver_cleartext.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: TheServer clear text password
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

tag_summary = "We were able to read the server.ini file
It may contain sensitive information like clear text passwords.
This flaw is known to affect TheServer.";

tag_solution = "upgrade your software or reconfigure it";

# References:
#
# Date:	 Mon, 14 Oct 2002 14:50:02 -0400 (EDT)
# From:	"Larry W. Cashdollar" <lwc@vapid.ath.cx>
# To:	bugtraq@securityfocus.com
# Subject: TheServer log file access password in cleartext w/vendor resolution.

if(description)
{
 script_id(11914);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2002-2389");
 script_bugtraq_id(5250);

 name = "TheServer clear text password";
 script_name(name);
 

 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Remote file access";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("misc_func.inc");

function testfile(port, no404, f)
{
  local_var	req, h, b, soc;

  soc = http_open_socket(port);
  if (!soc) return 0;
  req = http_get(port: port, item: f);
  send(socket: soc, data: req);
  h = http_recv_headers2(socket:soc);
  b = http_recv_body(socket: soc, headers: h);
  http_close_socket(soc);
  #display(h, "\n");
  #display(b, "\n");

  if (h =~ '^HTTP/[0-9.]+ +2[0-9][0-9]' && b)
  {
    if (! no404 || no404 >!< b)
      return 1;
  }
  return 0;
#if (egrep(string: b, pattern: "^ *password *=")) ...
}

port = get_http_port(default:80);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

no404 = get_kb_item("www/no404/" + port);

if (testfile(port: port, no404: no404, f: "/" + rand_str() + ".ini"))
  exit(0);

if (testfile(port: port, no404: no404, f: "/server.ini"))
  security_message(port);

