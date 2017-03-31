# OpenVAS Vulnerability Test
# $Id: squirrelmail_144.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: SquirrelMail < 1.4.4 XSS Vulnerabilities
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2005 George A. Theall
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

tag_summary = "The target is running at least one instance of SquirrelMail whose
version number suggests it is vulnerable to one or more cross-site
scripting vulnerabilities :

- Insufficient escaping of integer variables in webmail.php allows a
remote attacker to include HTML / script into a SquirrelMail webpage
(affects 1.4.0-RC1 - 1.4.4-RC1). 

- Insufficient checking of incoming URL vars in webmail.php allows an
attacker to include arbitrary remote web pages in the SquirrelMail
frameset (affects 1.4.0-RC1 - 1.4.4-RC1). 

- A recent change in prefs.php allows an attacker to provide a
specially crafted URL that could include local code into the
SquirrelMail code if and only if PHP's register_globals setting is
enabled (affects 1.4.3-RC1 - 1.4.4-RC1). 
 
***** OpenVAS has determined the vulnerability exists on the target
***** simply by looking at the version number of Squirrelmail 
***** installed there.";

tag_solution = "Upgrade to SquirrelMail 1.4.4 or later.";

if (description) {
  script_id(16228);
  script_version("$Revision: 3362 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(12337);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id(
    "CVE-2005-0075",
    "CVE-2005-0103", 
    "CVE-2005-0104"
  );
 
  name = "SquirrelMail < 1.4.4 XSS Vulnerabilities";
  script_name(name);
 
  summary = "Checks for Three XSS Vulnerabilities in SquirrelMail < 1.4.4";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2005 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("searching for 3 XSS vulnerabilities in SquirrelMail < 1.4.3 on port ", port, ".");


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/squirrelmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    if (ereg(pattern:"^1\.4\.([0-3](-RC.*)?|4-RC1)$", string:ver)) {
      security_message(port);
      exit(0);
    }
  }
}
