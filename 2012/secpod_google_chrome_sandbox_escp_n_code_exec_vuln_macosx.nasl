###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_sandbox_escp_n_code_exec_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Google Chrome Full Sandbox Escape and Code Execution Vulnerability (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to execute
arbitrary code.

Impact Level: System/Application";

tag_affected = "Google Chrome version 17.0.963.66 and prior on MAC OS X";

tag_insight = "The flaws are due to an use after free vulnerability in the default
installation of Chrome.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Google Chrome and is prone to sandbox
escape and code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903009");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-26 17:24:46 +0530 (Mon, 26 Mar 2012)");
  script_cve_id("CVE-2012-1846", "CVE-2012-1845");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome Full Sandbox Escape and Code Execution Vulnerability (MAC OS X)");
  script_xref(name : "URL" , value : "http://pwn2own.zerodayinitiative.com/status.html");
  script_xref(name : "URL" , value : "http://www.zdnet.com/blog/security/pwn2own-2012-google-chrome-browser-sandbox-first-to-fall/10588");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_require_keys("GoogleChrome/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome version <= 17.0.963.66
if(version_is_less_equal(version:chromeVer, test_version:"17.0.963.66")){
  security_message(0);
}
