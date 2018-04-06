###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_itunes_remote_code_exec_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apple iTunes Remote Code Execution Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the user running the affected application.
  Impact Level: Application";
tag_affected = "Apple iTunes version prior to 10.5.1 on Mac OS X";
tag_insight = "The flaw is due to the improper verification of authenticity of
  updates, allows man-in-the-middle attack execute arbitrary code via a
  Trojan horse update.";
tag_solution = "Upgrade to Apple Apple iTunes version 10.5.1 or later,
  For updates refer to http://www.apple.com/itunes/download/";
tag_summary = "This host is installed with Apple iTunes and is prone to remote
  code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902639");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2008-3434");
  script_bugtraq_id(50672);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-28 16:04:18 +0530 (Mon, 28 Nov 2011)");
  script_name("Apple iTunes Remote Code Execution Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5030");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4981");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2011/Nov/msg00003.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
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
  exit(0);
}

include("version_func.inc");

## Get Apple iTunes version from KB
itunesVer = get_kb_item("Apple/iTunes/MacOSX/Version");
if(itunesVer)
{
  ## Check for Apple iTunes versions < 10.5.1
  if(version_is_less(version:itunesVer, test_version:"10.5.1")){
    security_message(0);
  }
}
