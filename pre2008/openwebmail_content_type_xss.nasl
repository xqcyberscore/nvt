# OpenVAS Vulnerability Test
# $Id: openwebmail_content_type_xss.nasl 3398 2016-05-30 07:58:00Z antu123 $
# Description: Open WebMail Content-Type XSS
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

tag_summary = "The target is running at least one instance of Open WebMail whose
version is 2.32 or earlier.  Such versions are vulnerable to a cross
site scripting attack whereby an attacker can cause a victim to
unknowingly run arbitrary Javascript code by reading a MIME message
with a specially crafted Content-Type or Content-Description header. 
For further information, see :

  http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:05.txt
  http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt
  http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt

***** OpenVAS has determined the vulnerability exists on the target
***** simply by looking at the version number of Open WebMail
***** installed there.";

tag_solution = "Upgrade to Open WebMail version 2.32 20040603 or later.";

if (description) {
  script_id(12262);
  script_version("$Revision: 3398 $");
  script_bugtraq_id(10667);
  script_tag(name:"last_modification", value:"$Date: 2016-05-30 09:58:00 +0200 (Mon, 30 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  name = "Open WebMail Content-Type XSS";
  script_name(name);
 
  summary = "Checks for Content-Type XSS flaw in Open WebMail";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (debug_level) display("debug: checking for Content-Type XSS flaw in Open WebMail on ", host, ":", port, ".\n");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/openwebmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # nb: intermediate releases of 2.32 from 20040527 - 20040602 are 
    #     vulnerable, as are 2.32 and earlier releases.
    pat = "^(1\.|2\.([0-2]|3[01]|32$|32 20040(5|60[12])))";
    if (ereg(pattern:pat, string:ver)) {
      security_message(port);
      exit(0);
    }
  }
}
