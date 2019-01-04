###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_xss_vuln_dec18.nasl 12936 2019-01-04 04:46:08Z ckuersteiner $
#
# Dolibarr < 8.0.4 XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:dolibarr:dolibarr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112473");
  script_version("$Revision: 12936 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-04 05:46:08 +0100 (Fri, 04 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-28 12:59:11 +0100 (Fri, 28 Dec 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-19799");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr < 8.0.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr ERP/CRM is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to steal cookie-based authentication credentials,
  compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Dolibarr ERP/CRM version through 8.0.3.");

  script_tag(name:"solution", value:"Update to version 8.0.4 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/150623/Dolibarr-ERP-CRM-8.0.3-Cross-Site-Scripting.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "8.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
