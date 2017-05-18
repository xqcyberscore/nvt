# OpenVAS Vulnerability Test
# $Id: squirrelmail_html_injection_vuln.nasl 6053 2017-05-01 09:02:51Z teissa $
# Description: SquirrelMail From Email header HTML injection vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from George A. Theall <theall@tifaware.com>
# and Tenable Network Security
# modification by George A. Theall
# -change summary
# -remove references to global settings
# -clearer description
# -changed HTTP attack vector -> email
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
version number is between 1.2.0 and 1.2.10 inclusive.  Such versions do
not properly sanitize From headers, leaving users vulnerable to XSS
attacks.  Further, since SquirrelMail displays From headers when listing
a folder, attacks does not require a user to actually open a message,
only view the folder listing.

For example, a remote attacker could effectively launch a DoS against
a user by sending a message with a From header such as :

From:<!--<>(-->John Doe<script>document.cookie='PHPSESSID=xxx; path=/';</script><>

which rewrites the session ID cookie and effectively logs the user
out.

***** OpenVAS has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of Squirrelmail
***** installed there.";

tag_solution = "Upgrade to SquirrelMail 1.2.11 or later or wrap the call to
sqimap_find_displayable_name in printMessageInfo in
functions/mailbox_display.php with a call to htmlentities.";

#  Credit: SquirrelMail Team

if (description) {
  script_id(14217);
  script_version("$Revision: 6053 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10450);
  script_cve_id("CVE-2004-0639");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_xref(name:"OSVDB", value:"8292");

  name = "SquirrelMail From Email header HTML injection vulnerability";
  script_name(name);
 
 
  summary = "Check Squirrelmail for HTML injection vulnerability";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) 
	exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/squirrelmail"));
if (isnull(installs)) 
	exit(0);

foreach install (installs) 
{
	matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  	if (!isnull(matches)) 
	{
    		ver = matches[1];
    		dir = matches[2];

    		if (ereg(pattern:"^1\.2\.([0-9]|10)$", string:ver)) 
		{
      			security_message(port);
      			exit(0);
    		}
  	}
}


