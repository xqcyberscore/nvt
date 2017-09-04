###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_sep11_win02.nasl 7024 2017-08-30 11:51:43Z teissa $
#
# Mozilla Products Multiple Vulnerabilities - Sep 11 (Windows)
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

tag_solution = "Upgrade to Mozilla Firefox version 6.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.3 or later
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 6.0 or later
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to execute arbitrary code in the
  context of the user running an affected application. Failed exploit attempts
  will result in a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "Thunderbird version before 6
  SeaMonkey version 2.0 through 2.2
  Mozilla Firefox version 4.x through 5";
tag_insight = "The flaws are due to
  - An error when using Windows D2D hardware acceleration, allows attacker to
    obtain sensitive image data from a different domain.
  - Heap overflow in the Almost Native Graphics Layer Engine(ANGLE) library
    used in WebGL implementation.
  - Buffer overflow error in the WebGL shader implementation.
  - An error in the browser engine, it fails to implement WebGL, JavaScript
  - An error in the Ogg reader in the browser engine.";
tag_summary = "The host is installed with Mozilla firefox/thunderbird/seamonkey
  and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(802153);
  script_version("$Revision: 7024 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-30 13:51:43 +0200 (Wed, 30 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-2985", "CVE-2011-2986", "CVE-2011-2987",
                "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2991",
                "CVE-2011-2992");
  script_bugtraq_id(49224, 49227, 49226, 49242, 49239, 49243, 49245);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities - Sep 11 (Windows)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/45581");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-29.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl",
                      "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"5.0.1")){
     security_message(0);
     exit(0);
  }
}

# SeaMonkey Check
seaVer = get_kb_item("Seamonkey/Win/Ver");
if(seaVer)
{
  # Grep for SeaMonkey version
  if(version_in_range(version:seaVer, test_version:"2.0", test_version2:"2.2"))
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
  if(version_is_less(version:tbVer, test_version:"6.0")){
    security_message(0);
  }
}
