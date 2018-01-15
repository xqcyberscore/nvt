##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_opmanager_weak_enc_vuln.nasl 8368 2018-01-11 07:59:53Z asteins $
#
# ManageEngine OpManager Weak Encryption Algorithm Vulnerability
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

CPE = 'cpe:/a:zohocorp:manageengine_opmanager';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140279");
  script_version("$Revision: 8368 $");
  script_tag(name: "last_modification", value: "$Date: 2018-01-11 08:59:53 +0100 (Thu, 11 Jan 2018) $");
  script_tag(name: "creation_date", value: "2017-08-07 16:08:23 +0700 (Mon, 07 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2015-9107");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("ManageEngine OpManager Weak Encryption Algorithm Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_opmanager_detect.nasl");
  script_mandatory_keys("OpManager/installed");

  script_tag(name: "summary", value: "ManageEngine OpManager is prone to a weak encryption algorithm
vulnerability.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "Zoho ManageEngine OpManager uses a custom encryption algorithm to protect
the credential used to access the monitored devices. The implemented algorithm doesn't use a per-system key or
even a salt; therefore, it's possible to create a universal decryptor.");

  script_tag(name: "affected", value: "ManageEngine OpManager version 11 until 12.2.");

  script_tag(name: "solution", value: "No solution or patch is available as of 11th January, 2018. Information
regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://github.com/theguly/DecryptOpManager");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "11", test_version2: "12.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None available");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
