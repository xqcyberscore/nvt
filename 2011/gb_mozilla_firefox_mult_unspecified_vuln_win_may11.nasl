###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_unspecified_vuln_win_may11.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Mozilla Firefox Multiple Unspecified Vulnerabilities May-11 (Windows)
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

tag_impact = "Successful exploitation will allow remote attackers to a cause a denial of
  service or possibly execute arbitrary code.
  Impact Level: Application";
tag_affected = "Mozilla Firefox versions 4.x before 4.0.1";
tag_insight = "The flaws are due to multiple unspecified errors in the browser engine
  allow remote attackers to cause a denial of service or possibly execute
  arbitrary code via vectors related to gfx/layers/d3d10/ReadbackManagerD3D10.cpp
  and unknown other vectors.";
tag_solution = "Upgrade to Firefox version 4.0.1 or later
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox and is prone to multiple
  unspecified vulnerabilities.";

if(description)
{
  script_id(801886);
  script_version("$Revision: 5351 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-0079");
  script_bugtraq_id(47657);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Multiple Unspecified Vulnerabilities May-11 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44357/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/1127");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-12.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_summary("Check for the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  ## Grep for Firefox versions 4.x before 4.0.1
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"4.0.b12")){
    security_message(0);
  }
}
