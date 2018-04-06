###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln01_may13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Mozilla Firefox Multiple Vulnerabilities -01 May13 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption, bypass certain security restrictions and compromise
  a user's system.
  Impact Level: System/Application";

tag_affected = "Mozilla Firefox version before 21.0 on Mac OS X";
tag_insight = "- Unspecified vulnerabilities in the browser engine.
  - The Chrome Object Wrapper (COW) implementation does not prevent
    acquisition of chrome privileges.
  - Does not properly implement the INPUT element.
  - Does not properly maintain Mozilla Maintenance Service registry entries.
  - 'nsDOMSVGZoomEvent::mPreviousScale' and 'nsDOMSVGZoomEvent::mNewScale'
    functions do not initialize data structures.
  - Errors in 'SelectionIterator::GetNextSegment',
   'gfxSkipCharsIterator::SetOffsets' and '_cairo_xlib_surface_add_glyph'
   functions.
  - Use-after-free vulnerabilities in following functions,
    'nsContentUtils::RemoveScriptBlocker', 'nsFrameList::FirstChild', and
    'mozilla::plugins::child::_geturlnotify'.";
tag_solution = "Upgrade to Mozilla Firefox version 21.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "This host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803606");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1681", "CVE-2013-1680", "CVE-2013-1679", "CVE-2013-1678",
                "CVE-2013-1677", "CVE-2013-1676", "CVE-2013-1675", "CVE-2013-1674",
                "CVE-2013-1673", "CVE-2013-1672", "CVE-2013-1671", "CVE-2013-1670",
                "CVE-2013-1669", "CVE-2013-0801");
  script_bugtraq_id(59862, 59861, 59860, 59864, 59868, 59863, 59858, 59859, 59873,
                    59872, 59869, 59865, 59870, 59855);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-27 12:23:01 +0530 (Mon, 27 May 2013)");
  script_name("Mozilla Firefox Multiple Vulnerabilities -01 May13 (Mac OS X)");
  script_xref(name : "URL" , value : " http://secunia.com/advisories/53400");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028555");
  script_xref(name : "URL" , value : "http://www.dhses.ny.gov/ocs/advisories/2013/2013-051.cfm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Variable initialization
ffVer = "";

# Get the version from the kb
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  # Check for vulnerable version
  if(version_is_less(version:ffVer, test_version:"21.0"))
  {
    security_message(0);
    exit(0);
  }
}
