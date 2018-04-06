###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win_mar11.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities March-11 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_solution = "Upgrade to Firefox version 3.5.17 or 3.6.14 or later
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Seamonkey version 2.0.12 or later
  http://www.seamonkey-project.org/releases/";

tag_impact = "Successful exploitation will let attackers to cause a denial of service or
  execute arbitrary code or hijack the authentication of arbitrary users.
  Impact Level: Application";
tag_affected = "Seamonkey version before 2.0.12
  Firefox version before 3.5.17 and 3.6.x before 3.6.14";
tag_insight = "The flaws are due to:
   - An error when handling a recursive call to 'eval()' wrapped in a try or
     catch statement, which could be exploited to force a user into accepting
     any dialog.
   - A buffer overflow error related to the JavaScript engine's internal memory
     mapping of non-local JS variables, which could allow attackers to execute
     arbitrary code.
   - A user-after-free error related to a method used by 'JSON.stringify', which
     could allow attackers to execute arbitrary code.
   - A buffer overflow error related to the JavaScript engine's internal memory
     mapping of string values, which could allow attackers to execute arbitrary
     code.
   - An use-after-free error related to Web Workers, which could allow attackers
     to execute arbitrary code.
   - A cross-site request forgery (CSRF) vulnerability, allows remote attackers
     to hijack the authentication of arbitrary users for requests that were
     initiated by a plugin and received a 307 redirect to a page on a different
     web site.";
tag_summary = "The host is installed with Mozilla Firefox/Seamonkey that are prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801902");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-0051", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056",
                "CVE-2011-0057", "CVE-2011-0058", "CVE-2011-0059");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Vulnerabilities March-11 (Windows)");

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0531");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-02.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-03.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-04.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-05.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-06.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-07.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl");
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
  ## Grep for Firefox version < 3.5.17, 3.6.x < 3.6.14
  if(version_is_less(version:ffVer, test_version:"3.5.17") ||
     version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.13"))
    {
      security_message(0);
      exit(0);
    }
}

## Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  ## Grep for Seamonkey version 2.0.12
  if(version_is_less(version:smVer, test_version:"2.0.12")){
    security_message(0);
  }
}
