##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_debut_dos_vuln.nasl 7469 2017-10-18 06:23:14Z asteins $
#
# Debut Embedded Server DoS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.140295");
  script_version("$Revision: 7469 $");
  script_tag(name: "last_modification", value: "$Date: 2017-10-18 08:23:14 +0200 (Wed, 18 Oct 2017) $");
  script_tag(name: "creation_date", value: "2017-08-14 12:10:48 +0700 (Mon, 14 Aug 2017)");
  script_tag(name: "cvss_base", value: "7.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2017-12568");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("Debut Embedded Server DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("debut/banner");

  script_tag(name: "summary", value: "Debut embedded httpd server is prone to a denial of service vulnerability
which allows a remote attacker to hang the printer by sending a large amount of HTTP packets.");

  script_tag(name: "vuldetect", value: "Check the version.");

  script_tag(name: "affected", value: "Debut embedded httpd 1.20 (Brother/HP printer http admin)");

  script_tag(name: "solution", value: "No solution or patch is available as of 18th October, 2017. Information
regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://gist.github.com/tipilu/53f142466507b2ef4c8ceb08d22d1278");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default: 443);

banner = get_http_banner(port: port);

vers = eregmatch(pattern: "debut/([0-9.]+)", string: banner);

if (!isnull(vers[1])) {
  if (vers[1] == "1.20") {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "None");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
