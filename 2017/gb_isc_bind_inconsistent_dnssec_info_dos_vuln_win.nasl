##############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND Inconsistent DNSSEC Information Denial of Service Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810290");
  script_version("2019-07-05T09:54:18+0000");
  script_cve_id("CVE-2016-9147");
  script_bugtraq_id(95390);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2017-01-16 16:59:09 +0530 (Mon, 16 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ISC BIND Inconsistent DNSSEC Information Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  handling a query response containing inconsistent DNSSEC information.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure and daemon exit) via
  crafted data.");

  script_tag(name:"affected", value:"ISC BIND 9.9.9-P4, 9.9.9-S6, 9.10.4-P4 and
  9.11.0-P1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.9.9-P5 or
  9.9.9-S7 or 9.10.4-P5 or 9.11.0-P2 or later on Windows.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01440/0");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if( ! bindPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:bindPort ) ) exit( 0 );

bindVer = infos["version"];
proto = infos["proto"];

if(bindVer =~ "^(9\.)")
{
  if(version_is_equal(version:bindVer, test_version:"9.9.9.P4"))
  {
    fix = "9.9.9-P5";
    VULN = TRUE;
  }

  else if(version_is_equal(version:bindVer, test_version:"9.9.9.S6"))
  {
    fix = "9.9.9-S7";
    VULN = TRUE;
  }

  else if(version_is_equal(version:bindVer, test_version:"9.10.4.P4"))
  {
    fix = "9.10.4-P5";
    VULN = TRUE;
  }

  else if(version_is_equal(version:bindVer, test_version:"9.11.0.P1"))
  {
    fix = "9.11.0-P2";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:bindVer, fixed_version:fix);
  security_message(data:report, port:bindPort, proto:proto);
  exit(0);
}

exit(99);