###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_mult_dos_vuln_may18.nasl 9934 2018-05-23 11:48:03Z santu $
#
# ISC BIND Multiple Denial of Service Vulnerabilities-May18
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813401");
  script_version("$Revision: 9934 $");
  script_cve_id("CVE-2018-5736", "CVE-2018-5737");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-23 13:48:03 +0200 (Wed, 23 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-22 09:25:41 +0530 (Tue, 22 May 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND Multiple Denial of Service Vulnerabilities-May18");

  script_tag(name: "summary" , value:"The host is installed with ISC BIND and is
  prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to
  - An error in zone database reference counting while attempting several
    transfers of a slave zone in quick succession.

  - An error in the implementation of the new serve-stale feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure or degradation).

  Impact Level: Application");

  script_tag(name:"affected", value:"ISC BIND versions 9.12.0 and 9.12.1");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.12.1-P2 or
  later. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://kb.isc.org/article/AA-01606/0");
  script_xref(name : "URL" , value : "https://kb.isc.org/article/AA-01602/0");
  script_xref(name : "URL" , value : "https://www.isc.org");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed", "bind/version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe: CPE)){
  exit(0);
}

infos = get_app_version_and_proto(cpe:CPE, port:port, exit_no_version:TRUE);
version = infos["version"];
proto = infos["proto"];

if(version == "9.12.0" || version == "9.12.1")
{
  report = report_fixed_ver(installed_version: version, fixed_version: "9.12.1-P2");
  security_message(port:port, data: report, proto: proto);
  exit(0);
}
exit(0);
