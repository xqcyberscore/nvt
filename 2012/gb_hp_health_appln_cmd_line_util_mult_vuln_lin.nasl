###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_health_appln_cmd_line_util_mult_vuln_lin.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# HP System Health Application and Command Line Utilities Multiple Vulnerabilities
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_insight = "The flaws are due to unspecified errors in the application.

  NOTE: Further information is not available.";

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code via
  unknown vectors.
  Impact Level: System/Application";
tag_affected = "HP System Health Application and Command Line Utilities version prior to 9.0.0 on Linux";
tag_solution = "Upgrade HP System Health Application and Command Line Utilities version to 9.0.0 or later,
  For updates refer to http://www.hp.com/";
tag_summary = "The host is installed with HP System Health Application and Command
  Line Utilities and is prone to multiple unspecified vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802776");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-2000");
  script_bugtraq_id(53336);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-11 10:46:35 +0530 (Fri, 11 May 2012)");
  script_name("HP System Health Application and Command Line Utilities Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49051/");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/49051");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522549");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_hp_health_appln_cmd_line_utilities_detect_lin.nasl");
  script_require_keys("HP/Health/CLU");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
hpVer = "";

## Get the version from KB
hpVer = get_kb_item("HP/Health/CLU");
if(!hpVer){
  exit(0);
}

## Check for Hp Health Versions prior to 9.0.0
if(version_is_less(version:hpVer, test_version:"9.0.0")){
  security_message(0);
}
