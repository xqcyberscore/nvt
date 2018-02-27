###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_desktop_central_csrf_vuln.nasl 8940 2018-02-23 13:47:02Z santu $
#
# ManageEngine Desktop Central Cross-Site Request Forgery Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:zohocorp:manageengine_desktop_central";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812523");
  script_version("$Revision: 8940 $");
  script_cve_id("CVE-2014-9331");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-23 14:47:02 +0100 (Fri, 23 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-23 16:30:22 +0530 (Fri, 23 Feb 2018)");
  script_name("ManageEngine Desktop Central Cross-Site Request Forgery Vulnerability");

  script_tag(name: "summary" , value:"This host is installed with ManageEngine
  Desktop Central and is prone to cross-site request forgery vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw enables an anonymous attacker to
  add an admin account into the application. This leads to compromising the whole
  domain as the application normally uses privileged domain account to perform
  administration tasks.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to create administrator accounts, from browsers, where an authenticated
  Desktop Central user has logged on.

  Impact Level: Application");

  script_tag(name: "affected" , value:"ManageEngine Desktop Central before 9 build 90130");

  script_tag(name: "solution" , value:"Upgrade to ManageEngine Desktop Central build
  version 90130 or later. For updates refer to https://www.manageengine.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/archive/1/534604/100/0/threaded");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/desktop-central/cve20149331-cross-site-request-forgery.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_desktop_central_detect.nasl");
  script_mandatory_keys("ManageEngine/Desktop_Central/installed");
  script_require_ports("Services/www", 8040);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!mePort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:mePort, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"90130"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"Upgrade to build 90130", install_path:path);
  security_message(port:mePort, data:report);
  exit(0);
}
