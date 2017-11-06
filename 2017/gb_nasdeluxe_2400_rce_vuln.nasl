###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nasdeluxe_2400_rce_vuln.nasl 7660 2017-11-06 06:50:38Z cfischer $
#
# NASdeluxe NDL-2400R OS Command Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140489");
  script_version("$Revision: 7660 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-06 07:50:38 +0100 (Mon, 06 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-11-06 11:58:38 +0700 (Mon, 06 Nov 2017)");
  script_tag(name: "cvss_base", value: "10.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "WillNotFix");

  script_name("NASdeluxe NDL-2400R OS Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  
  script_tag(name: "summary", value: "NASdeluxe NDL-2400R is prone to an OS command injection vulnerability.");

  script_tag(name: "insight", value: "The language parameter in the web interface login request of the product
'NASdeluxe NDL-2400r' is vulnerable to an OS Command Injection as root.");

  script_tag(name: "vuldetect", value: "Check product.");

  script_tag(name: "solution", value: "The product has reached end-of-life (EOL) status since more than three
years. Thus, no patch will be provided by the vendor. It is recommended to remove this product.");

  script_xref(name: "URL", value: "https://www.exploit-db.com/exploits/40207/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("<title>NASdeluxe NDL-2400R</title>" >< res && "/usr/usrgetform.html?name=index" >< res) {
  report = "NASdeluxe NDL-2400R has been detected.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
