###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mem_crptn_vuln_win.nasl 3045 2016-04-11 13:50:48Z benallard $
#
# Google Chrome Windows Kernel Memory Corruption Vulnerability
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

tag_impact = "Successful exploitation could allow the attackers to execute arbitrary code
  or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 22.0.1229.79 on Windows 7";
tag_insight = "Unspecified error in application.";
tag_solution = "Upgrade to the Google Chrome 22.0.1229.79 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to memory
  corruption vulnerability.";

if(description)
{
  script_id(802975);
  script_version("$Revision: 3045 $");
  script_cve_id("CVE-2012-2897");
  script_bugtraq_id(55676);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-04-11 15:50:48 +0200 (Mon, 11 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-09-28 12:49:03 +0530 (Fri, 28 Sep 2012)");
  script_name("Google Chrome Windows Kernel Memory Corruption Vulnerability");
  script_xref(name : "URL" , value : "https://code.google.com/p/chromium/issues/detail?id=137852");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check the version of Google Chrome on Windows");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");

## Check for OS
if(hotfix_check_sp(win7:2, win7x64:2) <= 0){
  exit(0);
}

## Variable Initialization
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 22.0.1229.79
if(version_is_less(version:chromeVer, test_version:"22.0.1229.79")){
  security_message(0);
}
