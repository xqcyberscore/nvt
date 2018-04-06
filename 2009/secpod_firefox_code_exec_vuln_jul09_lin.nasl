###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_code_exec_vuln_jul09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Firefox Remote Code Execution Vulnerabilities July-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation could allow remote attacker to execute arbitrary code
  and results in Denial of Service condition.
  Impact Level:System/Application";
tag_affected = "Mozilla Firefox version prior to 3.0.12 and 3.5.1 on Linux.";
tag_insight = "Error exists when a page contains a Flash object which presents a slow script
  dialog, and the page is navigated while the dialog is still visible to the
  user, the Flash plugin is unloaded resulting in a crash due to a call to the
  deleted object.";
tag_solution = "Upgrade to Firefox version 3.0.12 or 3.5.1 or later
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Firefox browser and is prone to Remote
  Code Execution vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900399");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2467");
  script_bugtraq_id(35767);
  script_name("Mozilla Firefox Remote Code Execution Vulnerabilities July-09 (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35914");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1972");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-35.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer){
  exit(0);
}

# Grep for Firefox version < 3.0.12 and < 3.5.1
if(version_is_less(version:ffVer, test_version:"3.0.12") ||
   version_is_equal(version:ffVer, test_version:"3.5")){
  security_message(0);
}
