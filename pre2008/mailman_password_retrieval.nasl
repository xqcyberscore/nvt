# OpenVAS Vulnerability Test
# $Id: mailman_password_retrieval.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: Mailman Password Retrieval
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004-2005 George A. Theall
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

tag_summary = "The target is running version of the Mailman mailing list software that
allows a list subscriber to retrieve the mailman password of any other
subscriber by means of a specially crafted mail message to the server. 
That is, a message sent to $listname-request@$target containing the
lines :

    password address=$victim
    password address=$subscriber

will return the password of both $victim and $subscriber for the list
$listname@$target. 

***** OpenVAS has determined the vulnerability exists on the target
***** simply by looking at the version number of Mailman installed
***** there.";

tag_solution = "Upgrade to Mailman version 2.1.5 or newer.";
 
if (description) {
  script_id(12253);
  script_version("$Revision: 6046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2004-0412");
  script_bugtraq_id(10412);
  script_xref(name:"OSVDB", value:"6422");
  script_xref(name:"CLSA", value:"CLSA-2004:842");
  script_xref(name:"FLSA", value:"FEDORA-2004-1734");
  script_xref(name:"GLSA", value:"GLSA-200406-04");
  script_xref(name:"MDKSA", value:"MDKSA-2004:051");
 
  name = "Mailman Password Retrieval";
  script_name(name);
 
  summary = "Checks for Mailman Password Retrieval Vulnerability";

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004-2005 George A. Theall");

  family = "General";
  script_family(family);

  script_dependencies("global_settings.nasl", "http_version.nasl", "mailman_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("checking for Mailman Password Retrieval vulnerability on port ", port, ".");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/Mailman"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    if (ereg(pattern:"^2\.1(b[2-6]|rc1|\.[1-4]$)", string:ver)) {
      security_message(port);
      exit(0);
    }
  }
}
