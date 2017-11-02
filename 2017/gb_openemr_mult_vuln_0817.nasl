###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openemr_mult_vuln_0817.nasl 7610 2017-11-01 13:14:39Z jschulte $
#
# OpenEMR <= 5.0.0-3 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108206");
  script_version("$Revision: 7610 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-01 14:14:39 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-08-15 09:04:14 +0200 (Tue, 15 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_cve_id("CVE-2017-9380", "CVE-2017-12064");

  script_name("OpenEMR <= 5.0.0-3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value: "This host is installed with OpenEMR
    and is prone to multiple vulnerabilities");
  script_tag(name:"vuldetect", value:"Get the installed version with the help
    of detect NVT and check if the version is vulnerable or not.");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to:

        - bypass intended access restrictions via a crafted name

        - upload files of dangerous types as a low-privilege user which can result in arbitrary code execution within the context of the vulnerable application.");
  script_tag(name:"affected", value:"OpenEMR 5.0.0-3 and prior");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"solution", value:"No solution or patch is available as of 1st November, 2017. Information regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://www.wizlynxgroup.com/security-research-advisories/vuln/WLX-2017-002");
  script_xref(name: "URL", value: "https://github.com/openemr/openemr/commit/b8963a5ca483211ed8de71f18227a0e66a2582ad");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_is_less_equal(version: vers, test_version: "5.0.0-3")) {
   report = report_fixed_ver(installed_version: vers, fixed_version: "NoneAvailable");
   security_message(data: report, port: port);
   exit(0);
}
exit(99);
