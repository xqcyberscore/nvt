###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_snmp_agents_open_redirect_n_xss_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# HP SNMP Agents Open Redirect and Cross-site Scripting Vulnerabilities (Linux)
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

tag_impact = "Successful exploitation could allow attackers to execute script code in a
  user's browser session in context of an affected site.
  Impact Level: System/Application";
tag_affected = "HP SNMP Agents version prior to 9.0.0 on Linux";
tag_insight = "The flaws are due to input is not properly sanitised before being
  returned to the user and being used to redirect users.";
tag_solution = "Upgrade to the HP SNMP Agents 9.0.0 or later,
  For updates refer to http://www.hp.com/";
tag_summary = "The host is installed with HP SNMP Agents and is prone to open
  redirect and cross-site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802775");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-2001", "CVE-2012-2002");
  script_bugtraq_id(53340);
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-10 17:50:17 +0530 (Thu, 10 May 2012)");
  script_name("HP SNMP Agents Open Redirect and Cross-site Scripting Vulnerabilities (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48978/");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/48978");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522546");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_hp_snmp_agents_detect_lin.nasl");
  script_require_keys("HP/SNMP/Agents");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Variable Initialization
hpVer = "";

## Get the version from KB
hpVer = get_kb_item("HP/SNMP/Agents");
if(!hpVer){
  exit(0);
}

## Check for HP SNMP Agents Versions prior to 9.0.0
if(version_is_less(version:hpVer, test_version:"9.0.0")){
  security_message(0);
}
