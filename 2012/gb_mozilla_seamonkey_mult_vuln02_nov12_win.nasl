###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_seamonkey_mult_vuln02_nov12_win.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Mozilla SeaMonkey Multiple Vulnerabilities-02 November12 (Windows)
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

tag_impact = "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser.
  Impact Level: System/Application";
tag_affected = "SeaMonkey version before 2.14 on Windows";
tag_insight = "Multiple error exists
  - When combining SVG text with the setting of CSS properties.
  - Within the 'copyTexImage2D' implementation in the WebGL subsystem and
    in the XrayWrapper implementation.
  - Within 'str_unescape' in the Javascript engin and in 'XMLHttpRequest'
    objects created within sandboxes.";
tag_solution = "Upgrade to SeaMonkey version to 2.14 or later,
  http://www.mozilla.org/projects/seamonkey";
tag_summary = "This host is installed with Mozilla Seamonkey and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803353");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-4212", "CVE-2012-4213", "CVE-2012-4217", "CVE-2012-4217",
                "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-4208", "CVE-2012-5843",
                "CVE-2012-5836", "CVE-2012-5838");
  script_bugtraq_id(56629, 56628, 56633, 56634, 56618, 56614, 56632, 56611,
                    56631, 56636, 56642, 56637, 56635);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-11-26 12:30:03 +0530 (Mon, 26 Nov 2012)");
  script_name("Mozilla SeaMonkey Multiple Vulnerabilities-02 November12 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51358");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027791");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027792");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-91.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-94.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-96.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-97.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-99.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-105.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-106.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
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
seaVer = "";

# Get version from KB
seaVer = get_kb_item("Seamonkey/Win/Ver");

if(seaVer)
{
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.14"))
  {
    security_message(0);
    exit(0);
  }
}
