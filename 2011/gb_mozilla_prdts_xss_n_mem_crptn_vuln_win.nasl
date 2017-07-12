###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_xss_n_mem_crptn_vuln_win.nasl 6444 2017-06-27 11:24:02Z santu $
#
# Mozilla Products XSS and Memory Corruption Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Upgrade to Mozilla Firefox version 8.0 or 3.6.24 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Thunderbird version to 8.0 or 3.1.16 or later
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to inject arbitrary web script
  or HTML via crafted text with Shift JIS encoding and cause a denial of
  service.
  Impact Level: System/Application";
tag_affected = "Thunderbird version prior to 3.1.16, 5.0 through 7.0
  Mozilla Firefox version prior to 3.6.24, 4.x through 7.0";
tag_insight = "The flaws are due to
  - Error, while handling invalid sequences in the Shift-JIS encoding.
  - Crash, when using Firebug to profile a JavaScript file with many functions.";
tag_summary = "The host is installed with Mozilla firefox/thunderbird and is prone
  to cross site scripting and memory corruption vulnerabilities.";

if(description)
{
  script_id(802518);
  script_version("$Revision: 6444 $");
  script_cve_id("CVE-2011-3650", "CVE-2011-3648");
  script_bugtraq_id(50595, 50593);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-27 13:24:02 +0200 (Tue, 27 Jun 2017) $");
  script_tag(name:"creation_date", value:"2011-11-14 13:23:08 +0530 (Mon, 14 Nov 2011)");
  script_name("Mozilla Products XSS and Memory Corruption Vulnerabilities (Windows)");

  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-49.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-47.html");

  script_summary("Check for the version of Mozilla Firefox/Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl",
                           "gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"3.6.24") ||
     version_in_range(version:ffVer, test_version:"4.0", test_version2:"7.0"))
  {
     security_message(0);
     exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  # Grep for Thunderbird version
  if(version_is_less(version:tbVer, test_version:"3.1.16") ||
     version_in_range(version:ffVer, test_version:"4.0", test_version2:"7.0")){
    security_message(0);
  }
}
