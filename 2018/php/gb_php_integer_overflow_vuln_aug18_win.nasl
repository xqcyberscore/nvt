# Copyright (C) 2018 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813598");
  script_version("2019-08-08T10:05:16+0000");
  script_cve_id("CVE-2017-9120");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-08 10:05:16 +0000 (Thu, 08 Aug 2019)");
  script_tag(name:"creation_date", value:"2018-08-06 13:49:22 +0530 (Mon, 06 Aug 2018)");

  script_name("PHP Integer Overflow Vulnerability Aug18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to how mysqli_real_escape_string
  function in mysqli/mysqli_api.c file improperly handles long strings.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service by performing an integer overflow and therefore crashing the application.");

  script_tag(name:"affected", value:"PHP versions 7.0.x through 7.1.15.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=74544");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if(version_in_range(version:version, test_version:"7.0", test_version2:"7.1.15")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
