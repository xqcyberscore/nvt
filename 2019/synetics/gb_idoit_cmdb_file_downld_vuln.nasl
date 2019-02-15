##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_idoit_cmdb_file_downld_vuln.nasl 13683 2019-02-15 08:52:16Z mmartin $
#
# i-doit CMDB <= 1.12 Arbitrary File Download Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:synetics:i-doit";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141877");
  script_version("$Revision: 13683 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:52:16 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-15 14:16:19 +0700 (Tue, 15 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("i-doit CMDB <= 1.12 Arbitrary File Download Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_idoit_cmdb_detect.nasl");
  script_mandatory_keys("idoit_cmdb/detected");

  script_tag(name:"summary", value:"i-doit CMDB is prone to an authenticated arbitrary file download
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An authenticated attacker may download arbitrary files.");

  script_tag(name:"affected", value:"i-doit CMDB 1.12 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 15th February, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46133");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46134");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
