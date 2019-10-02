###############################################################################
# OpenVAS Vulnerability Test
#
# vBulletin Forum Arbitrary File Deletion And Remote Code Execution Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812354");
  script_version("2019-09-27T07:10:39+0000");
  script_cve_id("CVE-2017-17672");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-27 07:10:39 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2017-12-18 18:33:37 +0530 (Mon, 18 Dec 2017)");

  script_name("vBulletin Forum Arbitrary File Deletion And Remote Code Execution Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with vBulletin
  and is prone to arbitrary file deletion and remote code execution
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Unsafe usage of PHP's unserialize function in vB_Library_Template's cacheTemplates function, which is a
  publicly exposed API.

  - A deserialization vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary code execution and arbitrary file
  deletion on the affected system.");

  script_tag(name:"affected", value:"VBulletin versions through 5.3.4");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3569");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3573");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vbulletin/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vers, test_version:"5.3.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
