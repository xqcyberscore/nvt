###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_table_rename_information_disclosure_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# IBM DB2 Table Rename Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810704");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-1150");
  script_bugtraq_id(96597);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-09 15:35:12 +0530 (Thu, 09 Mar 2017)");
  script_name("IBM DB2 Table Rename Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running IBM DB2 and is
  prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when a table is renamed
  and a new table is created with the old name, users who had access on the old
  table may be able to access the new table.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated attacker with specialized access to tables that they should
  not be permitted to view.");

  script_tag(name:"affected", value:"IBM DB2 versions 11.1
  IBM DB2 versions 10.1 through FP5
  IBM DB2 versions 10.5 through FP7");

  script_tag(name:"solution", value:"Apply the appropriate fix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21999515");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/installed");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(!ibmPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ibmVer = get_app_version(cpe:CPE, port:ibmPort)){
  exit(0);
}

if(ibmVer =~ "^1001\.*")
{
  ## IBM DB2 10.1 through FP5
  ## IBM DB2 10.1 FP5  => 10015
  if(version_is_less_equal(version:ibmVer, test_version:"10015")){
    VULN = TRUE;
  }
}

if(ibmVer =~ "^1005\.*")
{
  ## IBM DB2 10.5 through FP7
  ## IBM DB2 10.5 FP7 => 10057
  if(version_is_less_equal(version:ibmVer, test_version:"10057")){
    VULN = TRUE;
  }
}

if(ibmVer =~ "^1101\.*")
{
  ## IBM DB2 11.1 FP 0
  ## IBM DB2 11.1 FP0 => 11010
  if(version_is_less_equal(version:ibmVer, test_version:"11010")){
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:ibmVer, fixed_version:"Apply appropriate fix");
  security_message(data:report, port:ibmPort);
  exit(0);
}
