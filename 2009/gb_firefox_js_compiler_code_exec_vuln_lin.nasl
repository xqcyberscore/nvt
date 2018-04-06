###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_js_compiler_code_exec_vuln_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Firefox JavaScript Compiler Code Execution Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Upgrade to detect non vulnerable version
#   - By sharaths <sharaths@secpod.com> On 2009-07-17
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

tag_impact = "Successful exploitation will let attackers to execute arbitrary code which
  results in memory corruption.
  Impact Level: Application";
tag_affected = "Firefox version 3.5 and prior on Linux";
tag_insight = "The flaw is due to an error when processing JavaScript code handling
  'font' HTML tags and can be exploited to cause memory corruption.";
tag_solution = "Upgrade to Firefox version 3.5.1 or later
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone
  to Remote Code Execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800844");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2477");
  script_bugtraq_id(35707);
  script_name("Mozilla Firefox JavaScript Compiler Code Execution Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35798");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9137");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1868");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-41.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
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

# Grep for Firefox version < 3.5.1
if(version_is_less(version:ffVer, test_version:"3.5.1")){
  security_message(0);
}
