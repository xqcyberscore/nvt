# OpenVAS Vulnerability Test
# $Id: basilix_arbitrary_command_execution.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: BasiliX Arbitrary Command Execution Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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

tag_summary = "The remote web server contains a PHP script that is prone to arbitrary
command execution.

Description :

The remote host appears to be running a version of BasiliX between
1.0.2beta or 1.0.3beta.  In such versions, the script 'login.php3'
fails to sanitize user input, which enables a remote attacker to pass
in a specially crafted value for the parameter 'username' with
arbitrary commands to be executed on the target using the permissions
of the web server.";

tag_solution = "Upgrade to BasiliX version 1.1.0 or later.";

if (description) {
  script_id(14304);
  script_version("$Revision: 6046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 
  script_bugtraq_id(3276);

  name = "BasiliX Arbitrary Command Execution Vulnerability";
  script_name(name);
 
 
  summary = "Checks for arbitrary command execution vulnerability in BasiliX";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");

  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  script_dependencies("basilix_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2001-09/0017.html");
  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.0\.[23]") {
    security_message(port);
    exit(0);
  }
}
