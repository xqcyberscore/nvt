###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_code_exec_vuln_win.nasl 8485 2018-01-22 07:57:57Z teissa $
#
# Mozilla Products Multiple vulnerabilities apr-10 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Upgrade to Firefox version 3.0.19, 3.5.9, 3.6.2
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Seamonkey version 2.0.4
  http://www.seamonkey-project.org/releases/";

tag_impact = "Successful exploitation will let attackers to execute arbitrary code on the
  system or cause the browser to crash.
  Impact Level: Application";
tag_affected = "Seamonkey version prior to 2.0.4 and
  Firefox version 3.0.x before 3.0.19, 3.5.x before 3.5.9, 3.6.x before 3.6.2";
tag_insight = "The flaws are due to:
  - A dangling pointer flaw in the 'nsPluginArray window.navigator.plugins object'
    when user loads specially crafted HTML which allows to execute arbitrary code
    via unknown vectors.
  - An error in loading a specially crafted applet, that converts a user mouse
    click into a 'drag-and-drop' action which allows to load a privileged
    'chrome:' URL and execute arbitrary scripting code with privileges.";
tag_summary = "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800754");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-0178", "CVE-2010-0177");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple vulnerabilities apr-10 (Windows)");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57393");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0748");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Mar/1023776.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl");
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
  # Grep for Firefox version 3.0 < 3.0.19, 3.5 < 3.5.9, 3.6 < 3.6.2
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.1") ||
     version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.8") ||
     version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.18"))
     {
       security_message(0);
       exit(0);
     }
}

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  # Grep for Seamonkey version < 2.0.4
  if(version_is_less(version:smVer, test_version:"2.0.4")){
    security_message(0);
  }
}
