# OpenVAS Vulnerability Test
# $Id: ilohamail_user_parameter.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IlohaMail User Parameter Vulnerability
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

tag_summary = "The target is running at least one instance of IlohaMail version
0.8.10 or earlier.  Such versions do not properly sanitize the 'user'
parameter, which could allow a remote attacker to execute arbitrary
code either on the target or in a victim's browser when a victim views
a specially crafted message with an embedded image as long as PHP's
magic quotes setting is turned off (it's on by default) and the MySQL
backend is in use. 

For a discussion of this vulnerability, see :

  http://sourceforge.net/mailarchive/forum.php?thread_id=3589704&forum_id=27701

***** OpenVAS has determined the vulnerability exists on the target
***** simply by looking at the version number of IlohaMail 
***** installed there.";

tag_solution = "Upgrade to IlohaMail version 0.8.11 or later.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.14637");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9131);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_xref(name:"OSVDB", value:"2879");
 
  name = "IlohaMail User Parameter Vulnerability";
  script_name(name);
 
  summary = "Checks for User Parameter vulnerability in IlohaMail";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for IlohaMail User Parameter vulnerability on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ver =~ "^0\.([0-7].*|8\.([0-9]|10)(-Devel)?$)") {
      security_message(port);
      exit(0);
    }
  }
}
