###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openemr_newlistname_sql_injec_vuln.nasl 10307 2018-06-25 05:05:34Z asteins $
#
# OpenEMR 'newlistname' Parameter SQL Injection Vulnerability
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

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813198");
  script_version("$Revision: 10307 $");
  script_cve_id("CVE-2018-9250");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-06-25 07:05:34 +0200 (Mon, 25 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-05-21 11:43:58 +0530 (Mon, 21 May 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenEMR 'newlistname' Parameter SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with OpenEMR and is
  prone to SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient validation
  of input data passed via 'newlistname' parameter to 'interface\super\edit_list.php'
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated attacker to execute arbitrary SQL commands on affected system.

  Impact Level: Application");

  script_tag(name:"affected", value:"OpenEMR versions before 5.0.1.1");

  script_tag(name:"solution", value:"Upgrade to OpenEMR version 5.0.1.1 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://www.open-emr.org");
  script_xref(name : "URL" , value : "https://github.com/openemr/openemr/pull/1578");
  script_xref(name : "URL" , value : "https://github.com/openemr/openemr/commit/2a5dd0601e1f616251006d7471997ecd7aaf9651");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed", "openemr/version");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!emrPort = get_app_port(cpe: CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:emrPort, exit_no_version:TRUE);
emrVer = infos['version'];
path = infos['location'];

if(version_is_less(version:emrVer, test_version:"5.0.1.1"))
{
  report = report_fixed_ver(installed_version:emrVer, fixed_version:"5.0.1.1", install_path:path);
  security_message(data:report, port:emrPort);
  exit(0);
}
exit(0);
