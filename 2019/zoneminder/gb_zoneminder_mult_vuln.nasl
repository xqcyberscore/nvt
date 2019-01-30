###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoneminder_mult_vuln.nasl 13345 2019-01-29 14:30:30Z asteins $
#
# ZoneMinder <= 1.32.3 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112504");
  script_version("$Revision: 13345 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-29 15:30:30 +0100 (Tue, 29 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-29 15:22:12 +0100 (Tue, 29 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-6990", "CVE-2019-6991", "CVE-2019-6992");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder <= 1.32.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_detect.nasl");
  script_mandatory_keys("zoneminder/installed");

  script_tag(name:"summary", value:"ZoneMinder is prone to multiple vulnerabilities.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A stored-self XSS in web/skins/classic/views/zones.php (CVE-2019-6990).

  - A classic Stack-based buffer overflow in the zmLoadUser() function in zm_user.cpp of the zmu binary (CVE-2018-6991).

  - A stored-self XSS in web/skins/classic/views/controlcaps.php (CVE-2019-6992).");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute code via a long username
  or execute HTML or JavaScript code via vulnerable fields.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Apply the provided patches.");

  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2444");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/commit/a3e8fd4fd5b579865f35aac3b964bc78d5b7a94a");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2478");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/pull/2482");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/commit/8c5687ca308e441742725e0aff9075779fa1a498");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/issues/2445");


  exit(0);
}

CPE = "cpe:/a:zoneminder:zoneminder";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less_equal(version: version, test_version: "1.32.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patches.");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
