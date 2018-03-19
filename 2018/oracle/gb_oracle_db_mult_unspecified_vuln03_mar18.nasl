###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_db_mult_unspecified_vuln03_mar18.nasl 9117 2018-03-16 13:48:01Z santu $
#
# Oracle Database Server Multiple Unspecified Vulnerabilities-03 March18
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
CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812797");
  script_version("$Revision: 9117 $");
  script_cve_id("CVE-2011-2248", "CVE-2011-0835", "CVE-2011-0880", "CVE-2011-0838",
                "CVE-2011-0832");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-03-16 14:48:01 +0100 (Fri, 16 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-07 15:14:30 +0530 (Wed, 07 Mar 2018)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities-03 March18");

  script_tag(name:"summary", value:"This host is running Oracle Database Server
  and is prone to multiple unspecified security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple 
  unspecified errors in components 'Core RDBMS' and 'SQL Performance Advisories/UIs'.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attackers to affect confidentiality, integrity, and availability via unknown
  vectors.

  Impact Level: Application");

  script_tag(name:"affected", value:"Oracle Database Server versions 11.1.0.7,
  11.2.0.1, 11.2.0.2");

  script_tag(name:"solution", value:"Apply patches from below link,
  https://www.oracle.com/technetwork/topics/security/cpujuly2011-313328.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "https://www.oracle.com/technetwork/topics/security/cpujuly2011-313328.html");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

dbport = "";
dbVer = "";

if(!dbport = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:dbport, exit_no_version:TRUE);
dbVer = infos['version'];
path = infos['location'];

affected = make_list('11.1.0.7', '11.2.0.1', '11.2.0.2');
foreach version (affected)
{
  if(dbVer == version)
  {
    report = report_fixed_ver(installed_version:dbVer, fixed_version: "Apply the patch", install_path:path);
    security_message(port:dbport, data:report);
    exit(0);
  }
}
exit(0);
