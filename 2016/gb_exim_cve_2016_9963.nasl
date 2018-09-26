##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exim_cve_2016_9963.nasl 11607 2018-09-25 13:53:15Z asteins $
#
# Exim Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:exim:exim';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106485");
  script_version("$Revision: 11607 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 15:53:15 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-12-23 10:52:32 +0700 (Fri, 23 Dec 2016)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-9963");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("gb_exim_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("exim/installed");

  script_tag(name:"summary", value:"Exim is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks the version.");

  script_tag(name:"insight", value:"If several conditions are met, Exim leaks private information to a remote
attacker.");

  script_tag(name:"impact", value:"A remote attacker may obtain private information.");

  script_tag(name:"affected", value:"Exim 4.69 until 4.87.");

  script_tag(name:"solution", value:"Update to Exim 4.87.1 or later.");

  script_xref(name:"URL", value:"https://bugs.exim.org/show_bug.cgi?id=1996");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.69", test_version2: "4.87")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.87.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
