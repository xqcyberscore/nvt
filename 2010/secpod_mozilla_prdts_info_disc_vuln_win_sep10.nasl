###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_info_disc_vuln_win_sep10.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# Mozilla Products 'js_InitRandom' Information Disclosure Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_solution = "Upgrade to Mozilla Firefox version 3.5.10 or 3.6.4 or later and
Seamonkey version 2.0.5 or later. For updates refer
- http://www.seamonkey-project.org/
- http://www.mozilla.org/en-US/firefox/new";

tag_impact = "Successful exploitation will let attackers to guess the seed value
via a brute-force attack.

Impact Level: Application";

tag_affected = "Mozilla Firefox version 3.5.x before 3.5.10
Mozilla Firefox version 3.6.x before 3.6.4
SeaMonkey version before 2.0.5.";

tag_insight = "The flaw is due to error in 'js_InitRandom' function in the
JavaScript implementation uses the current time for seeding of a random number
generator.";

tag_summary = "The host is installed with Mozilla Firefox and is prone to
Information Disclosure Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902306");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3400");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("Mozilla Products 'js_InitRandom' Information Disclosure Vulnerability (Windows)");

  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=475585");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl",
                           "gb_seamonkey_detect_win.nasl");
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
  # Grep for Firefox version 3.5.x before 3.5.10 and 3.6.x before 3.6.4
  if(version_in_range(version:ffVer, test_version:"3.5.0", test_version2:"3.5.9")||
     version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.3"))
  {
     security_message(0);
     exit(0);
  }
}

# SeaMonkey Check
seaVer = get_kb_item("Seamonkey/Win/Ver");
if(seaVer)
{
  # Grep for SeaMonkey version < 2.0.5
  if(version_is_less(version:seaVer, test_version:"2.0.5")){
     security_message(0);
  }
}
