###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win02_jul11.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities July-11 (Windows) - 02
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

tag_solution = "Upgrade to Firefox version 3.6.18, 5.0 or later.
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Thunderbird version 3.1.11 or later
  http://www.mozillamessaging.com/en-US/thunderbird/";

tag_impact = "Successful exploitation will allow remote attackers to bypass intended
  access restrictions, execute arbitrary code or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Thunderbird versions before 3.1.11
  Mozilla Firefox versions before 3.6.18 and 4.x through 4.0.1";
tag_insight = "- Multiple unspecified errors in the browser engine, allow remote attackers
    to cause a denial of service or possibly execute arbitrary code.
  - CRLF injection flaw in the nsCookieService::SetCookieStringInternal
    function in netwerk/cookie/nsCookieService.cpp, allows remote attackers to
    bypass intended access restrictions.";
tag_summary = "The host is installed with Mozilla Firefox or Thunderbird and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802217");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_cve_id("CVE-2011-2374", "CVE-2011-2605");
  script_bugtraq_id(48361);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities July-11 (Windows) - 02");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/44972/");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-19.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_thunderbird_detect_win.nasl");
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
  ## Grep for Firefox version before 3.6.18 and 4.x through 4.0.1
  if(version_is_less(version:ffVer, test_version:"3.6.18") ||
     version_in_range(version:ffVer, test_version:"4.0", test_version2:"4.0.1") ||
     version_in_range(version:ffVer, test_version:"4.0.b1", test_version2:"4.0.b12"))
  {
    security_message(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version < 3.1.11
   if(version_is_less(version:tbVer, test_version:"3.1.11")){
    security_message(0);
  }
}
