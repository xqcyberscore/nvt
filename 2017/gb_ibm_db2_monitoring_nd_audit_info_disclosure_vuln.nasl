###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_monitoring_nd_audit_info_disclosure_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# IBM DB2 'monitoring' and 'audit feature' Information Disclosure Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809855");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2014-0919");
  script_bugtraq_id(74217);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-04 11:08:09 +0530 (Wed, 04 Jan 2017)");
  script_name("IBM DB2 'monitoring' and 'audit feature' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running IBM DB2 and is
  prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to IBM DB2 stores
  passwords during the processing of certain SQL statements by the monitoring
  and audit facilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to obtain sensitive information via commands associated with
  these facilities.");

  script_tag(name:"affected", value:"IBM DB2 versions 9.5 through FP10
  IBM DB2 versions 9.7 through FP10
  IBM DB2 versions 9.8 through FP5
  IBM DB2 versions 10.1 through FP4
  IBM DB2 versions 10.5 through FP5");

  script_tag(name:"solution", value:"Apply the appropriate fix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1032247");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1032247");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21698021");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
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

if(ibmVer =~ "^0905\.*")
{
  ## IBM DB2 9.5 through FP10
  ## IBM DB2 9.5 FP10 => 090510
  if(version_is_less_equal(version:ibmVer, test_version:"090510"))
  {
    fix  = "IBM DB2 9.5 FP11";
    VULN = TRUE;
  }
}

else if(ibmVer =~ "^0907\.*")
{
  ## IBM DB2 9.7 through FP10
  ## IBM DB2 9.7 FP10 => 090710
  if(version_is_less_equal(version:ibmVer, test_version:"090710"))
  {
    fix  = "IBM DB2 9.7 FP11";
    VULN = TRUE;
  }
}

else if(ibmVer =~ "^0908\.*")
{
  ## IBM DB2 9.8 through FP5
  ## IBM DB2 9.8 FP5 => 09085
  if(version_is_less_equal(version:ibmVer, test_version:"09085"))
  {
    fix  = "IBM DB2 9.8 FP6";
    VULN = TRUE;
  }
}

else if(ibmVer =~ "^1001\.*")
{
  ## IBM DB2 10.1 through FP4
  ## IBM DB2 10.1 FP4  => 10014
  if(version_is_less_equal(version:ibmVer, test_version:"10014"))
  {
    fix  = "IBM DB2 10.1 FP5";
    VULN = TRUE;
  }
}

else if(ibmVer =~ "^1005\.*")
{
  ## IBM DB2 10.5 through FP4
  ## IBM DB2 10.5 FP5 => 10055
  if(version_is_less_equal(version:ibmVer, test_version:"10055"))
  {
    fix  = "IBM DB2 10.5 FP6";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:ibmVer, fixed_version:fix);
  security_message(data:report, port:ibmPort);
  exit(0);
}
