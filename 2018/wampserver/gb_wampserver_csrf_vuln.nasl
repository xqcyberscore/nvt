##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wampserver_csrf_vuln.nasl 9211 2018-03-27 05:28:01Z ckuersteiner $
#
# WampServer < 3.1.3 CSRF Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:wampserver:wampserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140891");
  script_version("$Revision: 9211 $");
  script_tag(name: "last_modification", value: "$Date: 2018-03-27 07:28:01 +0200 (Tue, 27 Mar 2018) $");
  script_tag(name: "creation_date", value: "2018-03-27 11:28:57 +0700 (Tue, 27 Mar 2018)");
  script_tag(name: "cvss_base", value: "6.8");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-8817");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("WampServer < 3.1.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wampserver_detect.nasl");
  script_mandatory_keys("wampserver/installed");

  script_tag(name: "summary", value: "WampServer is prone to a cross site request forgery (CSRF) vulnerability.");

  script_tag(name: "vuldetect", value: "Check the version.");

  script_tag(name: "affected", value: "WampServer 3.1.2 and prior.");

  script_tag(name: "solution", value: "Update to version 3.1.3 or later.");

  script_xref(name: "URL", value: "http://forum.wampserver.com/read.php?2%2C138295%2C150722%2Cpage%3D6%23msg-150722");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
