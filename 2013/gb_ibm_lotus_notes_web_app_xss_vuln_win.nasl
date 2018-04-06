###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_notes_web_app_xss_vuln_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# IBM Lotus Notes Web Application XSS Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: System/Application";

tag_affected = "IBM Lotus Notes Version 8.x before 8.5.3 FP3 on windows";
tag_insight = "An error exists within the Web applications which allows an attacker to read
  or set the cookie value by injecting script.";
tag_solution = "Upgrade to IBM Lotus Notes 8.5.3 FP3 or later,
  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg21619604";
tag_summary = "This host is installed with IBM Lotus Notes and is prone to cross
  site scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803215");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2012-4846");
  script_bugtraq_id(56944);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-23 13:22:09 +0530 (Wed, 23 Jan 2013)");
  script_name("IBM Lotus Notes Web Application XSS Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51593");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027887");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79535");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21619604");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ibm_lotus_notes_detect_win.nasl");
  script_require_keys("IBM/LotusNotes/Win/Ver");
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

lotusVer = "";

## Get for IBM Lotus Notes Version
lotusVer = get_kb_item("IBM/LotusNotes/Win/Ver");
if(!lotusVer){
 exit(0);
}

## Check for IBM Lotus Notes Version 8.x < 8.5.3 FP3 [8.5.33.12320]
## IBM Lotus Notes Version 8.5.3 FP2 versions is 8.5.32.12184
if(version_in_range(version:lotusVer, test_version:"8.5.0",
                                      test_version2:"8.5.32.12184")){
  security_message(0);
}
