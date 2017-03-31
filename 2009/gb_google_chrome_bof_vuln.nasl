###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_bof_vuln.nasl 4869 2016-12-29 11:01:45Z teissa $
#
# Google Chrome Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the attacker run arbitrary codes with the
  privilege of logged on user or can craft a special images or canvas to
  execute arbitrary code inside the sandboxed renderer (tab) process and cause
  a tab to crash.

  Impact level: Application";

tag_affected = "Google Chrome versions prior to 1.0.154.64, version 2.0.159.0 and prior.";
tag_insight = "These flaws are due to,
  - a boundary error in nitSkBitmapFromData() function while processing
    vectors related to large bitmap that arrives over the IPC channel.
  - a failure while validating the result of integer multiplication when
    computing image sizes.";
tag_solution = "Upgrade to version 1.0.154.64
  http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_id(800567);
  script_version("$Revision: 4869 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 12:01:45 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1441", "CVE-2009-1442");
  script_name("Google Chrome Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=10869");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2009/05/stable-update-security-fix.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(chromeVer == NULL){
  exit(0);
}

if(version_in_range(version:chromeVer, test_version:"2.0", test_version2:"2.0.159.0")||
   version_is_less (version:chromeVer, test_version:"1.0.154.64")){
  security_message(0);
}
