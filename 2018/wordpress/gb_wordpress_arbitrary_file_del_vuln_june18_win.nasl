###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_arbitrary_file_del_vuln_june18_win.nasl 10371 2018-06-29 13:27:39Z santu $
#
# WordPress Arbitrary File Deletion Vulnerability-June 2018 (Windows)
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813454");
  script_version("$Revision: 10371 $");
  script_cve_id("CVE-2018-12895");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-06-29 15:27:39 +0200 (Fri, 29 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-27 12:51:49 +0530 (Wed, 27 Jun 2018)");
  script_name("WordPress Arbitrary File Deletion Vulnerability-June 2018 (Windows)");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to arbitrary file deletion vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  sanitization of user input data in the 'wp-includes/post.php' script before
  passing on to a file deletion function.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to delete any file of the wordPress installation and any other file
  on the server on which the PHP process user has the proper permissions to delete.
  Also capability of arbitrary file deletion can be used to circumvent some
  security measures and execute arbitrary code on the webserver.

  Impact Level: Application");

  script_tag(name: "affected" , value:"All wordPress versions through version 4.9.6
  on Windows");

  script_tag(name: "solution" , value:"No known solution is available as of
  27th June, 2018. Information regarding this issue will be updated once
  solution details are available. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution");
  script_xref(name : "URL" , value : "https://wordpress.org/download");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wordPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:wordPort, exit_no_version:TRUE);
vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vers, test_version:"4.9.6"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report, port:wordPort);
  exit(0);
}
exit(0);
