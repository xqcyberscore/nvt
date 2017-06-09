###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_epolicy_orchestrator_mult_vuln01_aug13.nasl 6104 2017-05-11 09:03:48Z teissa $
#
# McAfee ePolicy Orchestrator (ePO) Multiple Vulnerabilities-01 August13
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "
  Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803864";
CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6104 $");
  script_cve_id("CVE-2013-0140", "CVE-2013-0141");
  script_bugtraq_id(59500, 59505);
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-11 11:03:48 +0200 (Thu, 11 May 2017) $");
  script_tag(name:"creation_date", value:"2013-08-09 14:52:18 +0530 (Fri, 09 Aug 2013)");
  script_name("McAfee ePolicy Orchestrator (ePO) Multiple Vulnerabilities-01 August13");

 tag_summary =
"This host is running McAfee ePolicy Orchestrator and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help detect NVT and check the version is
vulnerable or not.";

  tag_insight =
"Flaws are due to improper sanitation of user supplied input via 'uid'
parameter to /EPOAGENTMETA/DisplayMSAPropsDetail.do script and specifically
directory traversal style (e.g., ../../).";

  tag_impact =
"Successful exploitation will allow remote attackers to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or
disclosure of arbitrary data";

  tag_affected =
"McAfee ePolicy Orchestrator (ePO) version before 4.5.7 and 4.6.x before 4.6.6";

  tag_solution =
"Upgrade to McAfee ePolicy Orchestrator version 5.0 or 4.6.6 or 4.5.7 or later,
For updates refer to http://www.mcafee.com/in/products/epolicy-orchestrator.aspx";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53196");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/209131");
  script_xref(name : "URL" , value : "https://kc.mcafee.com/corporate/index?page=content&id=SB10042");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");
  script_require_ports("Services/www", 8443);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
vers = "";
port = 0;

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  exit(0);
}

## Get Symantec Web Gateway version
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## check the vulnerable versions
if(vers)
{
  if(version_is_less(version:vers, test_version:"4.5.7") ||
     version_in_range(version:vers, test_version:"4.6.0", test_version2:"4.6.5"))
  {
    security_message(port);
    exit(0);
  }
}
