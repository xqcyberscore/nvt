###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_olap_query_dos_vuln.nasl 6093 2017-05-10 09:03:18Z teissa $
#
# IBM DB2 OLAP Specification Query Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803788";
CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6093 $");
  script_cve_id("CVE-2013-6717");
  script_bugtraq_id(64336);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2013-12-26 17:35:04 +0530 (Thu, 26 Dec 2013)");
  script_name("IBM DB2 OLAP Specification Query Denial of Service Vulnerability");

   tag_summary =
"This host is running IBM DB2 and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version of IBM DB2 with the help of detect NVT and check
the version is vulnerable or not.";

  tag_insight =
"An unspecified flaw related to the OLAP query engine.";

  tag_impact =
"Successful exploitation will allow attacker to cause denial of service
conditions.

Impact Level: Application";

  tag_affected =
"IBM DB2 versions 9.7 through FP9
IBM DB2 versions 9.8 through FP5
IBM DB2 versions 10.1 through FP3
IBM DB2 versions 10.5 through FP2 ";

  tag_solution =
"The fix for this vulnerability is available for download for DB2 V9.7 FP9
http://www-01.ibm.com/support/docview.wss?uid=swg24036646

For DB2 V9.8, V10.1 and V10.5, the fix is planned to be made available in
future fix packs.
http://www-01.ibm.com/support/docview.wss?uid=swg21660041 ";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56012");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/89116");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21660041");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/installed");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ibmVer  = "";
ibmPort = "";

if(!ibmPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(!ibmVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:ibmPort)){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  ## IBM DB2 9.7 through FP9
  ## IBM DB2 9.7 FP8 => 09079
  if(version_is_less_equal(version:ibmVer, test_version:"09079")){
    security_message(port:ibmPort);
  }
}

if(ibmVer =~ "^0908\.*")
{
  ## IBM DB2 9.8 through FP5
  ## IBM DB2 9.8 FP5 => 09085
  if(version_is_less_equal(version:ibmVer, test_version:"09085")){
    security_message(port:ibmPort);
  }
}

if(ibmVer =~ "^1001\.*")
{
  ## IBM DB2 10.1 through FP3
  ## IBM DB2 10.1 FP2  => 10013
  if(version_is_less_equal(version:ibmVer, test_version:"10013"))
  {
    security_message(port:ibmPort);
    exit(0);
  }
}

if(ibmVer =~ "^1005\.*")
{
  ## IBM DB2 10.5 through FP2
  ## IBM DB2 10.5 FP1 => 10052
  if(version_is_less_equal(version:ibmVer, test_version:"10052"))
  {
    security_message(port:ibmPort);
    exit(0);
  }
}
