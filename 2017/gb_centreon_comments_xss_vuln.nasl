###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_centreon_comments_xss_vuln.nasl 8242 2017-12-22 14:01:22Z cfischer $
#
# Centreon 'Comments' POST Parameter Cross Site Scripting Vulnerability
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

CPE = "cpe:/a:centreon:centreon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811735");
  script_version("$Revision: 8242 $");
  script_cve_id("CVE-2015-7672");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 15:01:22 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-09-11 13:47:50 +0530 (Mon, 11 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Centreon 'Comments' POST Parameter Cross Site Scripting Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with Centreon
  and is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to insufficient
  sanitization of input passed via 'Comments' POST parameter to main.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary scripts in the logged-in user's web browser.

  Impact Level: Application");

  script_tag(name:"affected", value:"Centreon version 2.6.1");

  script_tag(name:"solution", value:"No solution or patch is available as of 22nd
  December, 2017. Information regarding this issue will be updated once solution details
  are available. For updates refer to https://www.centreon.com ");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "https://www.youtube.com/watch?v=sIONzwQAngU");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("centreon_detect.nasl");
  script_mandatory_keys("centreon/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!cenPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!cenVer = get_app_version(cpe:CPE, port:cenPort)){
  exit(0);
}

if(version_is_equal(version:cenVer, test_version:"2.6.1"))
{
  report = report_fixed_ver(installed_version:cenVer, fixed_version:"None Available");
  security_message(data:report, port:cenPort);
  exit(0);
}
exit(99);
