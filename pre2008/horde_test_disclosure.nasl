# OpenVAS Vulnerability Test
# $Id: horde_test_disclosure.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Horde and IMP test disclosure
#
# Authors:
# Sverre H. Huseby <shh@thathost.com>
#
# Copyright:
# Copyright (C) 2004 Sverre H. Huseby
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

tag_summary = "The remote server is running Horde and/or IMP with test scripts
available from the outside.  The scripts may leak server-side
information that is valuable to an attacker.";

tag_solution = "test.php and imp/test.php should be deleted,
or they should be made unreadable by the web server.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11617");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  name = "Horde and IMP test disclosure";
  script_name(name);

  summary = "Checks if test.php is available in Horde or IMP";


  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");

  script_copyright("Copyright 2004 (C) Sverre H. Huseby");
  family = "Web application abuses";
  script_family(family);

  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("horde/installed");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

files = make_list(
  "/test.php", "/test.php3",
  "/imp/test.php", "/imp/test.php3"
);

# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  d = matches[2];

  foreach f (files) {
    req = http_get(item:string(d, f), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if (res == NULL)
      exit(0);

    if ('PHP Version' >< res
        && ('Horde Version' >< res || 'IMP Version' >< res)) {
      security_message(port);
      exit(0);
    }
  }
}
