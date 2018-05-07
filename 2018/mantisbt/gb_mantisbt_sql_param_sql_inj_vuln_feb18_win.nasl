###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_sql_param_sql_inj_vuln_feb18_win.nasl 9738 2018-05-07 04:50:48Z ckuersteiner $
#
# MantisBT 'sql' Parameter SQL Injection Vulnerability - Feb18 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812753");
  script_version("$Revision: 9738 $");
  script_cve_id("CVE-2018-6382");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-07 06:50:48 +0200 (Mon, 07 May 2018) $");
  script_tag(name:"creation_date", value:"2018-02-05 11:55:27 +0530 (Mon, 05 Feb 2018)");

  script_name("MantisBT 'sql' Parameter SQL Injection Vulnerability - Feb18 (Windows)");

  script_tag(name:"summary", value:"The vendor disputes the significance of this report because server.php is
intended to execute arbitrary SQL statements on behalf of authenticated users from 127.0.0.1, and the issue does
not have an authentication bypass.

This host is installed with MantisBT and is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation
  of user supplied input via 'sql' parameter in via the 
  'vendor/adodb/adodb-php/server.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow local 
  users to conduct SQL Injection attacks and if there is no configuration, 
  the physical path address is leaked.

  Impact Level: Application");

  script_tag(name:"affected", value:"MantisBT version 2.10.0 on Windows");

  script_tag(name:"solution", value:"The vendor disputed the vulnerability and therefore will not provide a fix.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://archive.is/vs3Hy#selection-1317.21-1317.27");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/installed", "Host/runs_windows");
  script_require_ports("Services/www", 80);

  script_tag(name: "deprecated", value: TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");

if(!manPort = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:manPort, exit_no_version:TRUE)) exit(0);
manVer = infos['version'];
path = infos['location'];

if(manVer == "2.10.0")
{
  report = report_fixed_ver(installed_version: manVer, fixed_version: "NoneAvailable", install_path:path);
  security_message(port: manPort, data: report);
  exit(0);
}
exit(0);
