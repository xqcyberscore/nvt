###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_nov11_win.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Mozilla Products Multiple Vulnerabilities (Windows)
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

tag_solution = "Upgrade to Mozilla Firefox version 8.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Thunderbird version to 8.0 or later
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to cause denial of service and
  execute arbitrary code via unspecified vectors.
  Impact Level: System/Application";
tag_affected = "Thunderbird version 7.0
  Mozilla Firefox version 7.0";
tag_insight = "The flaws are due to
  - unspecified erros in the browser engine.
  - Direct2D (aka D2D) API is used in conjunction with the Azure graphics
    back-end on windows.";
tag_summary = "The host is installed with Mozilla firefox/thunderbird and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(802511);
  script_version("$Revision: 5351 $");
  script_cve_id("CVE-2011-3651", "CVE-2011-3649");
  script_bugtraq_id(50597, 50591);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-11-11 15:10:19 +0530 (Fri, 11 Nov 2011)");
  script_name("Mozilla Products Multiple Vulnerabilities (Windows)");

  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-50.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-48.html");
  script_summary("Check for the version of Mozilla Firefox/Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl",
                      "gb_thunderbird_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver", "Thunderbird/Win/Ver");
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
  if(version_is_equal(version:ffVer, test_version:"7.0"))
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
  if(version_is_equal(version:tbVer, test_version:"7.0")){
    security_message(0);
  }
}
