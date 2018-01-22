###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_unspecified_vuln_mar10_lin.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Mozilla Firefox Unspecified Vulnerability Mar-10 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Impact is currently unknown.
  Impact Level: Application";
tag_affected = "Mozilla Firefox version 3.5.x through 3.5.8 on Linux.";
tag_insight = "Vulnerability details are currently not available.";
tag_solution = "Upgrade to Mozilla Firefox version 3.6.3 or later
  For updates refer to http://www.mozilla.com/en-US/firefox/upgrade.html";
tag_summary = "The host is installed with mozilla Firefox and is prone to
  unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902148");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-1122");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Unspecified Vulnerability Mar-10 (Linux)");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/392231.php");
  script_xref(name : "URL" , value : "http://www.security-database.com/cvss.php?alert=CVE-2010-1122");

  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_GATHER_INFO);
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

## Get Firefox version from KB
fpVer = get_kb_item("Firefox/Linux/Ver");
if(!fpVer){
  exit(0);
}

## Check for Mozilla Firefox Version  3.5 to 3.5.8
if(version_in_range(version:fpVer, test_version:"3.5.0", test_version2:"3.5.8")){
   security_message(0);
}
