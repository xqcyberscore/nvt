# OpenVAS Vulnerability Test
# $Id: imp_html_plus_time_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IMP HTML+TIME XSS Vulnerability
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

tag_solution = "Upgrade to IMP version 3.2.5 or later.";

tag_summary = "The remote server is running at least one instance of IMP whose version
number is 3.2.4 or lower.  Such versions are vulnerable to a
cross-scripting attack whereby an attacker may be able to inject
arbitrary content, including script, in a specially crafted MIME
message.  To have an effect, the victim must be using Internet Explorer
to access IMP and be using the inline MIME viewer for HTML messages. 

This vulnerability is a variation on the one reported here :

  - http://www.greymagic.com/security/advisories/gm005-mc/

Note : OpenVAS has determined the vulnerability exists on the target
simply by looking at the version number of IMP installed there, it has
not attempted to actually exploit the vulnerability.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.13857");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2004-1443");
  script_bugtraq_id(10845);
  script_xref(name:"OSVDB", value:"8293");

  name = "IMP HTML+TIME XSS Vulnerability";
  script_name(name);
 
  summary = "Checks for HTML+TIME Vulnerability in IMP";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "imp_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for HTML+TIME XSS vulnerability in IMP on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/imp"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ereg(pattern:"^(1\.|2\.|3\.(0|1|2|2\.[1-4]))$", string:ver)) {
      security_message(port);
      exit(0);
    }
  }
}
