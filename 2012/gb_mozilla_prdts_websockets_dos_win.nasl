###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_websockets_dos_win.nasl 3046 2016-04-11 13:53:51Z benallard $
#
# Mozilla Firefox 'WebSockets' Denial of Service Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let attackers to cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary
  code via unspecified vectors.
  Impact Level: System/Application";
tag_affected = "Mozilla Firefox versions before 16.0.1 on Windows";
tag_insight = "Error in the WebSockets implementation, allows remote attackers to cause a
  denial of service.";
tag_solution = "Upgrade to Mozilla Firefox version 16.0.1 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla firefox and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802996);
  script_version("$Revision: 3046 $");
  script_cve_id("CVE-2012-4191");
  script_bugtraq_id(55889);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-04-11 15:53:51 +0200 (Mon, 11 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-10-15 17:43:07 +0530 (Mon, 15 Oct 2012)");
  script_name("Mozilla Firefox 'WebSockets' Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50856");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50935");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-88.html");
  script_summary("Check for the vulnerable version of Mozilla Firefox on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
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

# Variable Initialization
ffVer = "";

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"16.0.1"))
  {
    security_message(0);
    exit(0);
  }
}
