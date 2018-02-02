###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbulletin_forum_file_del_n_rce_vuln.nasl 8627 2018-02-01 15:16:06Z cfischer $
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
  script_version("$Revision: 8627 $");
  script_cve_id("CVE-2017-17672");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-01 16:16:06 +0100 (Thu, 01 Feb 2018) $");
  script_tag(name:"creation_date", value:"2017-12-18 18:33:37 +0530 (Mon, 18 Dec 2017)");
  script_name("vBulletin Forum Arbitrary File Deletion And Remote Code Execution Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with vBulletin
  and is prone to arbitrary file deletion and remote code execution
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,
  - Unsafe usage of PHP's unserialize function in vB_Library_Template's cacheTemplates
    function, which is a publicly exposed API.
  - A deserialization vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary code execution and arbitrary file
  deletion on the affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"VBulletin versions through 5.3.4");

  script_tag(name:"solution", value:"No solution or patch is available as of
  01th February, 2018. Information regarding this issue will be updated once
  solution details are available. For updates refer to http://www.vbulletin.com");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "https://blogs.securiteam.com/index.php/archives/3569");
  script_xref(name : "URL" , value : "https://blogs.securiteam.com/index.php/archives/3573");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vBulletin/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

vPort = "";
vVer = "";

if(!vPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location( cpe:CPE, port:vPort, exit_no_version:TRUE)) exit(0);
vVer = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vVer, test_version:"5.3.4"))
{
  report = report_fixed_ver(installed_version:vVer, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report, port:vPort);
  exit(0);
}
exit(0);
