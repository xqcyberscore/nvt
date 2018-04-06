###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_itunes_code_exec_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apple iTunes Arbitrary Code Execution Vulnerability (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to lead to an unexpected
  application termination or arbitrary code execution.
  Impact Level: System/Application";
tag_affected = "Apple iTunes version prior to 10.2.2";
tag_insight = "The flaw is due to memory corruption issue exist in WebKit. A
  man-in-the-middle attack while browsing the iTunes Store via iTunes may lead
  to an unexpected application termination or arbitrary code execution.";
tag_solution = "Upgrade to Apple iTunes version 10.2.2 or later
  For updates refer to http://www.apple.com/itunes/download/";
tag_summary = "This host has installed apple iTunes and is prone to arbitrary code
  execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902720");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-1290", "CVE-2011-1344");
  script_bugtraq_id(46849, 46822);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Apple iTunes Arbitrary Code Execution Vulnerability (Mac OS X)");


  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("secpod_itunes_detect_macosx.nasl");
  script_require_keys("Apple/iTunes/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce//2011//Apr/msg00004.html");
  exit(0);
}

include("version_func.inc");

## Get Apple iTunes version from KB
itunesVer = get_kb_item("Apple/iTunes/MacOSX/Version");
if(itunesVer)
{
  ## Check for Apple iTunes versions < 10.2.2
  if(version_is_less(version:itunesVer, test_version:"10.2.2")){
    security_message(0);
  }
}
