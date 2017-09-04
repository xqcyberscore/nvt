###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win02_may11.nasl 7006 2017-08-25 11:51:20Z teissa $
#
# Mozilla Products Multiple Vulnerabilities May-11 (Windows) - 02
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_solution = "Upgrade to Firefox version 3.5.19, 3.6.17, 4.0.1 or later
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Seamonkey version 2.0.14 or later
  http://www.seamonkey-project.org/releases/

  Upgrade to Thunderbird version 3.1.10 or later
  http://www.mozillamessaging.com/en-US/thunderbird/";

tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information or execute arbitrary code in the context of the user running the
  affected application.
  Impact Level: Application";
tag_affected = "SeaMonkey versions before 2.0.14.
  Thunderbird version before 3.1.10
  Mozilla Firefox versions 3.5.19 and 3.6.x before 3.6.17.";
tag_insight = "- An error in the implementation of the 'resource:' protocol can be exploited
    to perform directory traversal attacks and disclose sensitive information.
  - Multiple errors in the browser engine can be exploited to corrupt memory
    and potentially execute arbitrary code.";
tag_summary = "The host is installed with Mozilla Firefox, Seamonkey or Thunderbird and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(801885);
  script_version("$Revision: 7006 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-25 13:51:20 +0200 (Fri, 25 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0074",
                "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078",
                "CVE-2011-0080");
  script_bugtraq_id(47666,47655,47646,47647,47648,47651);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities May-11 (Windows) - 02");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/44357/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/1127");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-12.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl",
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

## Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  ## Grep for Firefox version before 3.5.19 and 3.6.x before 3.6.17
  if(version_is_less(version:ffVer, test_version:"3.5.19") ||
     version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.16"))
  {
    security_message(0);
    exit(0);
  }
}

## Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  ## Grep for Seamonkey version 2.0.14
  if(version_is_less(version:smVer, test_version:"2.0.14"))
  {
    security_message(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version < 3.1.10
  if(version_is_less(version:tbVer, test_version:"3.1.10")){
    security_message(0);
  }
}
