###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_v8_remote_code_exec_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Google Chrome V8 Remote Code Execution Vulnerability (Mac OS X)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code,
  cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 15.0.874.121 on Mac OS X";
tag_insight = "The flaw is due to an out-of-bounds write operation error in V8
  (JavaScript engine) causing memory corruption.";
tag_solution = "Upgrade to the Google Chrome 15.0.874.121 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to remote
  code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902637");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3900");
  script_bugtraq_id(50701);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-21 17:55:43 +0530 (Mon, 21 Nov 2011)");
  script_name("Google Chrome V8 Remote Code Execution Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46889/");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/11/stable-channel-update_16.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_require_keys("GoogleChrome/MacOSX/Version");
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

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 15.0.874.121
if(version_is_less(version:chromeVer, test_version:"15.0.874.121")){
  security_message(0);
}
