###############################################################################
# OpenVAS Vulnerability Test
#
# Serv-U 'SITE SET TRANSFERPROGRESS ON' Command Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:serv-u:serv-u";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100338");
  script_version("2019-06-24T07:41:01+0000");
  script_tag(name:"last_modification", value:"2019-06-24 07:41:01 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"creation_date", value:"2009-11-04 20:13:20 +0100 (Wed, 04 Nov 2009)");
  script_bugtraq_id(36585);
  script_cve_id("CVE-2009-3655");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Serv-U 'SITE SET TRANSFERPROGRESS ON' Command Remote Denial of Service Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_solarwinds_serv-u_consolidation.nasl");
  script_mandatory_keys("solarwinds/servu/detected");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the references
  for details.");

  script_tag(name:"summary", value:"Serv-U is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow attackers to deny
  service to legitimate users.");

  script_tag(name:"affected", value:"Serv-U 7.0.0.1 through 8.2.0.3 are vulnerable. Other versions may also
  be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36585");
  script_xref(name:"URL", value:"http://www.serv-u.com/releasenotes/");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "7.0.0.1", test_version2: "8.2.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
