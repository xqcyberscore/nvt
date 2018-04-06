###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_drda_req_dos_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# IBM DB2 Distributed Relational Database Architecture Request DoS Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation allows remote users to cause denial
  of service.
  Impact Level: Application.";
tag_affected = "IBM DB2 version 9.1 before FP11,
  IBM DB2 version 9.5 before FP9,
  IBM DB2 version 9.7 before FP5 and
  IBM DB2 version 9.8 before FP4";
tag_insight = "The flaw is caused due an error within the server component can be exploited
  to cause a crash by sending a specially crafted Distributed Relational
  Database Architecture request.";
tag_solution = "Upgrade to IBM DB2 version 9.1 FP11, 9.5 FP8, 9.7 FP5, 9.8 FP4 or later,
  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg27007053";
tag_summary = "The host is running IBM DB2 and is prone to denial of service
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802729");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0710");
  script_bugtraq_id(52326);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-04-03 10:37:46 +0530 (Tue, 03 Apr 2012)");
  script_name("IBM DB2 Distributed Relational Database Architecture Request DoS Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48279/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73494");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21588090");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC76899");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg27007053");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_require_keys("IBM-DB2/Remote/ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Variable Initialization
ibmVer = "";

ibmVer = get_kb_item("IBM-DB2/Remote/ver");
if(!ibmVer){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  # IBM DB2 9.7 FP 5 => 09075
  if(version_is_less(version:ibmVer, test_version:"09075"))
  {
    security_message(0);
    exit(0);
  }
}

if(ibmVer =~ "^0901\.*")
{
  # IBM DB2 9.1 FP 11 => 090111
  if(version_is_less(version:ibmVer, test_version:"090111"))
  {
    security_message(0);
    exit(0);
  }
}

if(ibmVer =~ "^0905\.*")
{
  # IBM DB2 9.5 FP 9 => 09059
  if(version_is_less(version:ibmVer, test_version:"09059"))
  {
    security_message(0);
    exit(0);
  }
}

if(ibmVer =~ "^0908\.*")
{
  # IBM DB2 9.8 FP 4 => 09084
  if(version_is_less(version:ibmVer, test_version:"09084")){
    security_message(0);
  }
}
