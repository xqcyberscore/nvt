###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_insecure_lib_load_vuln_win.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# Mozilla Products Insecure Library Loading Vulnerability (Windows)
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

tag_impact = "Successful exploitation will allow the attackers to execute
arbitrary code and conduct DLL hijacking attacks.

Impact Level: Application";

tag_affected = "Thunderbird version 3.1.2
SeaMonkey version 2.0.6
Firefox version 3.6.8 and prior on Windows.";

tag_insight = "The flaw is due to the application insecurely loading certain
librairies from the current working directory, which could allow attackers to
execute arbitrary code by tricking a user into opening a file.";

tag_solution = "Upgrade Thunderbird to 3.1.3 or later
Upgrade SeaMonkey to 2.0.7 or later
Upgrade Firefox 3.6.9 or later
http://www.mozilla.com/en-US/firefox/all.html
http://www.mozillamessaging.com/en-US/thunderbird";

tag_summary = "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird
and is prone to insecure library loading vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902242");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3131");
  script_name("Mozilla Products Insecure Library Loading Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41095");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14783/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2169");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/513324/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl",
                       "gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  ## Grep for Firefox version < 3.6.9
  if(version_is_less_equal(version:ffVer, test_version:"3.6.8"))
  {
    security_message(0);
    exit(0);
  }
}

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  # Grep for Seamonkey version 2.0.6
  if(version_is_equal(version:smVer, test_version:"2.0.6"))
  {
    security_message(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version 3.1.2
  if(version_is_equal(version:tbVer, test_version:"3.1.2")){
    security_message(0);
  }
}
