###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_utl_file_module_dir_trav_vuln_win.nasl 5079 2017-01-24 11:00:33Z cfi $
#
# IBM DB2 UTL_FILE Module Directory Traversal Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation allows remote users to modify, delete or read
  arbitrary files via a pathname in the file field.
  Impact Level: Application";
tag_affected = "IBM DB2 version 10.1 before FP1 on Windows";
tag_insight = "The flaw is caused due an improper validation of user-supplied input by
  routines within the UTL_FILE module. Which allows attackers to read arbitrary
  files.";
tag_solution = "Upgrade to IBM DB2 version 10.1 FP1 or later,
  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg1IC85513";
tag_summary = "The host is running IBM DB2 and is prone to directory traversal
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802463";
CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5079 $");
  script_cve_id("CVE-2012-3324");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:00:33 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2012-09-27 15:12:59 +0530 (Thu, 27 Sep 2012)");
  script_name("IBM DB2 UTL_FILE Module Directory Traversal Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/77924");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC85513");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21611040");

  script_summary("Check for the version of IBM DB2 on Windiows ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl", "os_detection.nasl");
  script_require_keys("IBM-DB2/Remote/ver");
  script_require_keys("IBM-DB2/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Only windows platform are affected
## if its not windows exit
if(host_runs("windows") != "yes"){
 exit(0);
}

## Variable Initialization
vers = "";
ibmVer  = "";

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(!get_port_state(port)){
  exit(0);
}

if(!ibmVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

# IBM DB2 10.1 FP 0 => 10010
if(version_is_equal(version:ibmVer, test_version:"10010")){
  security_message(port:port);
}
