###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_soliddb_sql_spc_dos_vuln.nasl 6074 2017-05-05 09:03:14Z teissa $
#
# IBM solidDB Stored Procedure Call Handling Denial of Service Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803761";
CPE = "cpe:/a:ibm:soliddb";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6074 $");
  script_cve_id("CVE-2013-3031");
  script_bugtraq_id(59637);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-05 11:03:14 +0200 (Fri, 05 May 2017) $");
  script_tag(name:"creation_date", value:"2013-09-20 12:22:19 +0530 (Fri, 20 Sep 2013)");
  script_name("IBM solidDB Stored Procedure Call Handling Denial of Service Vulnerability");

   tag_summary =
"This host is running IBM solidDB and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version of IBM solidDB with the help of detect NVT and check
the version is vulnerable or not.";

  tag_insight =
"The flaw is due to an error when calling stored procedures without input
parameters when the parameters have default values. This can be exploited
to trigger an exception and cause the server to shutdown.";

  tag_impact =
"Successful exploitation will allow attacker to cause a denial of service.

Impact Level: Application";

  tag_affected =
"IBM solidDB 6.0.x before 6.0.1070, 6.3.x before 6.3.0.56,
6.5.x before 6.5.0.12, and 7.0.x before 7.0.0.4 ";

  tag_solution =
"Upgrade IBM solidDB to 6.0.1070, 6.3.0.56, 6.5.0.12, 7.0.0.4 or later,
http://www-03.ibm.com/software/products/us/en/ibmsoli";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53299");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/84593");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21643599");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC94044");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC94043");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC88797");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC88796");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_soliddb_detect.nasl");
  script_mandatory_keys("IBM-soliddb/installed");
  exit(0);
}


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

## Check for the version 6.0.x before 6.0.1070
if(ibmVer =~ "^6\.0\.*")
{
  if(version_is_less(version:ibmVer, test_version:"6.0.1070"))
  {
    security_message(port:ibmPort);
    exit(0);
  }
}

## Check the version 6.3.x before 6.3.56(06.30.0056)
if(ibmVer =~ "^06\.3.*")
{
  if(version_is_less(version:ibmVer, test_version:"06.30.0056"))
  {
    security_message(port:ibmPort);
    exit(0);
  }
}

## Check the version 6.5.x before 6.5.0.12
if(ibmVer =~ "^6\.5\.*")
{
  if(version_is_less(version:ibmVer, test_version:"6.5.0.12"))
  {
    security_message(port:ibmPort);
    exit(0);
  }
}

## Check the version 7.0.x before 7.0.0.4
if(ibmVer =~ "^7\.0\.*")
{
  if(version_is_less(version:ibmVer, test_version:"7.0.0.4")){
    security_message(port:ibmPort);
  }
}
