###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_info_disc_vuln_feb18_win.nasl 9094 2018-03-14 07:52:16Z cfischer $
#
# PostgreSQL Information Disclosure Vulnerability-Feb18 (Windows)
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812954");
  script_version("$Revision: 9094 $");
  script_cve_id("CVE-2018-1053");
  script_bugtraq_id(102986);
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-03-14 08:52:16 +0100 (Wed, 14 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-28 10:48:11 +0530 (Wed, 28 Feb 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PostgreSQL Information Disclosure Vulnerability-Feb18 (Windows)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to a information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not");

  script_tag(name:"insight", value:"The flaw exists as the application creates
  temporary files in an insecure manner, where all temporary files made with
  'pg_upgrade' are world-readable");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated attacker to gain access to sensitive information that may aid
  in further attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.x before 9.3.21,
  9.4.x before 9.4.16, 9.5.x before 9.5.11, 9.6.x before 9.6.7 and 10.x before
  10.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL version 10.2 or 9.6.7
  or 9.5.11 or 9.4.16 or 9.3.21 or later.
  For updates refer to http://www.postgresql.org/download");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.postgresql.org/about/news/1829");
  script_xref(name : "URL" , value : "https://www.postgresql.org/docs/current/static/release-10-2.html");
  script_xref(name : "URL" , value : "https://www.postgresql.org/docs/current/static/release-9-6-7.html");
  script_xref(name : "URL" , value : "https://www.postgresql.org/docs/current/static/release-9-5-11.html");
  script_xref(name : "URL" , value : "https://www.postgresql.org/docs/current/static/release-9-4-16.html");
  script_xref(name : "URL" , value : "https://www.postgresql.org/docs/current/static/release-9-3-21.html");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl","os_detection.nasl");
  script_mandatory_keys("PostgreSQL/installed","Host/runs_windows");
  script_require_ports("Services/postgresql", 5432);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

pgsqlPort = "";
pgsqlVer = "";
fix = "";
pgsqlPath = "";

pgsqlPort = get_app_port(cpe:CPE);
if(!pgsqlPort){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:pgsqlPort, exit_no_version:TRUE);
pgsqlVer = infos['version'];
pgsqlPath = infos['location'];

if(pgsqlVer =~ "^(9\.3)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.3.21")){
    fix = "9.3.21";
  }
}

else if(pgsqlVer =~ "^(9\.4)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.4.16")){
    fix = "9.4.16";
  }
}

else if(pgsqlVer =~ "^(9\.5)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.5.11")){
    fix = "9.5.11";
  }
}

else if(pgsqlVer =~ "^(9\.6)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.6.7")){
    fix = "9.6.7";
  }
}

else if(pgsqlVer =~ "^(10\.)")
{
  if(version_is_less(version:pgsqlVer, test_version:"10.2")){
    fix = "10.2";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version: pgsqlVer, fixed_version: fix, install_path:pgsqlPath);
  security_message(port:pgsqlPort, data: report);
  exit(0);
}
exit(0);
