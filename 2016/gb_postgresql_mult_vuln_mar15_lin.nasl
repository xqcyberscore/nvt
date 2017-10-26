###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_mult_vuln_mar15_lin.nasl 7545 2017-10-24 11:45:30Z cfischer $
#
# PostgreSQL Multiple Vulnerabilities - Mar15 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807518");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-0773", "CVE-2016-0766");
  script_bugtraq_id(83184);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-03-10 19:31:43 +0530 (Thu, 10 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("PostgreSQL Multiple Vulnerabilities - Mar15 (Linux)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to the PostgreSQL
  incorrectly handle certain regular expressions and certain configuration
  settings (GUCS) for users of PL/Java.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to escalate privileges and to cause denial of service 
  conditions.

  Impact Level: Application");

  script_tag(name:"affected", value:"PostgreSQL version before 9.1.20, 9.2.x 
  before 9.2.15, 9.3.x before 9.3.11, 9.4.x before 9.4.6, and 9.5.x before 
  9.5.1 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 9.1.20 or 9.2.15 or 
  9.3.11 or 9.4.6 or 9.5.1 or higher, 
  For updates refer to http://www.postgresql.org/download");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.ubuntu.com/usn/USN-2894-1");
  script_xref(name : "URL" , value : "http://www.postgresql.org/about/news/1644");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl","os_detection.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed","Host/runs_unixoide");
  exit(0);
}


include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

## Variable Initialization
pgsqlPort = "";
pgsqlVer = "";

## Get the default port
pgsqlPort = get_app_port(cpe:CPE);
if(!pgsqlPort){
  exit(0);
}

## Get the PostgreSQL version
pgsqlVer = get_app_version(cpe:CPE, port:pgsqlPort);
if(isnull(pgsqlVer)){
  exit(0);
}

if(version_is_less(version:pgsqlVer, test_version:"9.1.20"))
{
  fix = "9.1.20";
  VULN = TRUE;
}

else if(pgsqlVer =~ "^(9\.2)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.2.15"))
  {
    fix = "9.2.15";
    VULN = TRUE;
  }
}

else if(pgsqlVer =~ "^(9\.3)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.3.11"))
  {
    fix = "9.3.11";
    VULN = TRUE;
  }
}

else if(pgsqlVer =~ "^(9\.4)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.4.6"))
  { 
    fix = "9.4.6";
    VULN = TRUE;
  }
}

else if(pgsqlVer =~ "^(9\.5)")
{
  if(version_is_less(version:pgsqlVer, test_version:"9.5.1"))
  {
    fix = "9.5.1";
    VULN = TRUE;
  }
}

if(VULN)
{
    report = report_fixed_ver(installed_version:pgsqlVer, fixed_version:fix);
    security_message(data:report, port:pgsqlPort);
    exit(0);
}

exit(99);