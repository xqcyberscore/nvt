###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_xss_vuln_PMASA-2018-3_lin.nasl 10352 2018-06-28 07:09:51Z santu $
#
# phpMyAdmin Cross-Site Scripting Vulnerability (PMASA-2018-3)-Linux
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813451");
  script_version("$Revision: 10352 $");
  script_cve_id("CVE-2018-12581");
  script_bugtraq_id(104530);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-06-28 09:09:51 +0200 (Thu, 28 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-26 15:47:09 +0530 (Tue, 26 Jun 2018)");
  script_name("phpMyAdmin Cross-Site Scripting Vulnerability (PMASA-2018-3)-Linux");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin and
  is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient validation
  of input passed to 'js/designer/move.js' script in phpMyAdmin.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to inject arbitrary web script or HTML via crafted database name.

  Impact Level: Application");

  script_tag(name:"affected", value:"phpMyAdmin versions prior to 4.8.2 on Linux");

  script_tag(name:"solution", value:"Upgrade to version 4.8.2 or newer. For
  updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2018-3");

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("Host/runs_unixoide", "phpMyAdmin/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe: CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"4.8.2"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.8.2", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}
exit(0);
