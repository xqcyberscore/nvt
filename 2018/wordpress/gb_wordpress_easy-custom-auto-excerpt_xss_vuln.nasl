###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_easy-custom-auto-excerpt_xss_vuln.nasl 8395 2018-01-12 11:26:51Z asteins $
#
# WordPress Easy Custom Auto Excerpt Plugin XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112189");
  script_version("$Revision: 8395 $");
  script_tag(name: "last_modification", value: "$Date: 2018-01-12 12:26:51 +0100 (Fri, 12 Jan 2018) $");
  script_tag(name: "creation_date", value: "2018-01-12 12:10:00 +0100 (Fri, 12 Jan 2018)");
  script_tag(name: "cvss_base", value: "4.3");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-5311");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "WillNotFix");

  script_name("WordPress Easy Custom Auto Excerpt Plugin XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name: "summary", value: "Easy Custom Auto Excerpt plugin for WordPress is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "affected", value: "WordPress Easy Custom Auto Excerpt plugin up to and including version 2.4.6.");

  script_tag(name: "solution", value: "No solution or patch available. Likely none will be provided anymore since the plugin is no longer available via the WordPress plugin site.

Either find another way to patch this plugin or uninstall it if you want to mitigate the issue.");

  script_xref(name: "URL", value: "https://github.com/d4wner/Vulnerabilities-Report/blob/master/easy-custom-auto-excerpt.md");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/easy-custom-auto-excerpt/readme.txt");

if ("=== Easy Custom Auto Excerpt ===" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "= ([0-9.]+) =", string: res);

  if (!isnull(vers[1]) && version_is_less_equal(version: vers[1], test_version: "2.4.6")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "None Available");
    security_message(port: port, data: report);
    exit(0);
  }
}
exit(0);
