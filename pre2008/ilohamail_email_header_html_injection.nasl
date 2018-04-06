# OpenVAS Vulnerability Test
# $Id: ilohamail_email_header_html_injection.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IlohaMail Email Header HTML Injection Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
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

tag_summary = "The remote web server contains a PHP script which is vulnerable to a cross site
scripting vulnerability.

Description :

The target is running at least one instance of IlohaMail version
0.8.12 or earlier.  Such versions do not properly sanitize message
headers, leaving users vulnerable to XSS attacks.  For example, a
remote attacker could inject Javascript code that steals the user's
session cookie and thereby gain access to that user's account.";

tag_solution = "Upgrade to IlohaMail version 0.8.13 or later.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.14634");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10668);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  name = "IlohaMail Email Header HTML Injection Vulnerability";
  script_name(name);
 
 
  summary = "Checks for Email Header HTML Injection vulnerability in IlohaMail";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for IlohaMail Email Header HTML Injection vulnerability on ", host, ":", port, ".\n");

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

   if (ver =~ "^0\.([0-7].*|8\.([0-9]|1[0-2])(-Devel)?$)") {
      security_message(port);
      exit(0);
    }
  }
}
