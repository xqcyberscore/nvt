###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tika_server_junrar_dos_vuln.nasl 10299 2018-06-22 11:50:53Z santu $
#
# Apache Tika Server Junrar Denial of Service Vulnerability
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813536");
  script_version("$Revision: 10299 $");
  script_cve_id("CVE-2018-12418");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-06-22 13:50:53 +0200 (Fri, 22 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-20 16:32:04 +0530 (Wed, 20 Jun 2018)");
  script_name("Apache Tika Server Junrar Denial of Service Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Apache Tika Server
  and is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an infinite loop when
  handling corrupt RAR files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to perform denial of service.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache Tika Server versions through latest release 1.18");

  script_tag(name:"solution", value:"No known solution is available as of 20th June, 2018.
  Information regarding this issue will be updated once solution details are available.
  For updates refer to Reference links.");
 
  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "https://github.com/junrar/junrar/commit/ad8d0ba8e155630da8a1215cee3f253e0af45817");
  script_xref(name : "URL" , value : "https://tika.apache.org");
  
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_server_detect.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");
  script_require_ports("Services/www", 9998, 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!tPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:tPort, exit_no_version:TRUE);
tVer = infos['version'];
tPath = infos['location'];

if(version_is_less_equal(version:tVer, test_version:"1.18"))
{
  report = report_fixed_ver(installed_version:tVer, fixed_version:"None Available", install_path:tPath);
  security_message(data:report, port:tPort);
  exit(0);
}
exit(0); 
