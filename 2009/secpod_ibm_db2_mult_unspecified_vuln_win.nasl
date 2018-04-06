###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_db2_mult_unspecified_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# IBM DB2 Multiple Unspecified Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to bypass security restrictions,
  cause a denial of service and some are having unknown impact.
  Impact Level: System/Application";
tag_affected = "IBM DB2 version 9.5 prior to FP 5
  IBM DB2 version 9.7 prior to FP 1";
tag_insight = "The flaws are due to:
  - An unspecified error in RAND scalar function in the common code infrastructure
    component when the Database Partitioning Feature (DPF) is used.
  - An error in common code infrastructure component does not properly validate
    the size of a memory pool during a creation attempt, which allows attackers
    to cause a denial of service via unspecified vectors.
  - An error in install component when configures the High Availability (HA)
    scripts with incorrect file-permission and authorization settings.";
tag_solution = "Update IBM DB2 9.5 FP 5 or 9.7 FP 1,
  http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678";
tag_summary = "The host is installed with IBM DB2 and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901074");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4326", "CVE-2009-4327", "CVE-2009-4331");
  script_bugtraq_id(37332);
  script_name("IBM DB2 Multiple Unspecified Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37759");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3520");
  script_xref(name : "URL" , value : "ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v95/APARLIST.TXT");
  script_xref(name : "URL" , value : "ftp://ftp.software.ibm.com/ps/products/db2/fixes/english-us/aparlist/db2_v97/APARLIST.TXT");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Databases");
  script_dependencies("secpod_ibm_db2_detect_win_900218.nasl");
  script_require_keys("Win/IBM-db2/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

ibmVer = get_kb_item("Win/IBM-db2/Ver");
if(!ibmVer){
  exit(0);
}

# Check for IBM DB2 Version 9.5 before 9.5 FP5 (9.5 FP 5 = 9.5.500.784)
# Check for IBM DB2 Version 9.7 before 9.7 FP1 (9.7 FP 1 => 9.7.100.177)
if(version_in_range(version:ibmVer, test_version:"9.5", test_version2:"9.5.500.783")||
   version_in_range(version:ibmVer, test_version:"9.7", test_version2:"9.7.100.176")){
  security_message(0);
}
