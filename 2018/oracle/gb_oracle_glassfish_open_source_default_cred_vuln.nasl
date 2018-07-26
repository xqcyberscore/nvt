###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_open_source_default_cred_vuln.nasl 10637 2018-07-26 09:34:03Z santu $
#
# Oracle GlassFish Open Source Default Credentials Vulnerability
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813576");
  script_version("$Revision: 10637 $");
  script_cve_id("CVE-2018-14324");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-07-26 11:34:03 +0200 (Thu, 26 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-17 12:45:41 +0530 (Tue, 17 Jul 2018)");
  script_name("Oracle GlassFish Open Source Default Credentials Vulnerability");

  script_tag(name:"summary", value:"This host is running Oracle GlassFish Server
  and is prone to default credentials vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to demo feature in Oracle 
  GlassFish Open Source Edition has TCP port 7676 open by default with a password 
  of admin for the admin account.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain potentially sensitive information, perform database operations, or
  manipulate the demo via a JMX RMI session.

  Impact Level: Application");

  script_tag(name:"affected", value:"Oracle GlassFish Server versions 5.0");

  script_tag(name:"solution", value:"No known solution is available as of 17th July, 2018.
  Information regarding this issue will be updated once solution details are available.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name: "URL", value: "https://github.com/javaee/glassfish/issues/22500");
  script_xref(name: "URL", value: "http://www.oracle.com/");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!glPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE, port:glPort);
glVer = infos['version'];
glPath = infos['location'];

if(version_is_equal(version:glVer, test_version:"5.0"))
{
  report = report_fixed_ver(installed_version:glVer, fixed_version:"NoneAvailable", install_path:glPath);
  security_message(data:report, port:glPort);
  exit(0);
}
