# OpenVAS Vulnerability Test
# $Id: phorum_register_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Phorum register.php Cross-Site Scripting
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote version of Phorum contains a script called 'register.php'
which is vulnerable to a cross-site scripting attack.  An attacker may
exploit this problem to steal the authentication credentials of third
party users.";

tag_solution = "Upgrade to Phorum 5.0.18 or later.";

#  Ref: Scott Dewey

if (description) {
script_oid("1.3.6.1.4.1.25623.1.0.19584");
script_version("$Revision: 9348 $");
script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
script_bugtraq_id(14726);
script_cve_id("CVE-2005-2836");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
name = "Phorum register.php Cross-Site Scripting";
script_name(name);

script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
script_copyright("This script is Copyright (C) 2005 David Maciejak");

family = "Web application abuses";
script_family(family);

script_dependencies("phorum_detect.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");

script_tag(name : "solution" , value : tag_solution);
script_tag(name : "summary" , value : tag_summary);
script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2005-09/0018.html");
exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([0-4]\..*|5\.0\.([0-9][^0-9]*|1[0-7][^0-9]*))$")
    security_message(port);
}
