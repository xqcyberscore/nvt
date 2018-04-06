###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_mar12_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities - Mar12 (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_solution = "Upgrade to Mozilla Firefox version 3.6.28 or 11.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.8 or later,
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 3.1.20 or 11 or later,
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code via unknown vectors.
  Impact Level: System/Application";
tag_affected = "SeaMonkey version before 2.8
  Thunderbird ESR version 10.x before 10.0.3
  Mozilla Firefox ESR version 10.x before 10.0.3
  Thunderbird version before 3.1.20 and 5.0 through 10.0
  Mozilla Firefox version before 3.6.28 and 4.x through 10.0";
tag_insight = "The flaws are due to
  - Multiple unspecified vulnerabilities in the browser engine.
  - An improper implementation of the nsWindow failing to validate an instance
    after event dispatching.
  - An error when handling 'javascript:'.
  - A use-after-free error exists within the
    'nsSMILTimeValueSpec::ConvertBetweenTimeContainers()' function.
  - An improper implementation of SVG Filters.";
tag_summary = "The host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802821");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0461", "CVE-2012-0463", "CVE-2012-0458", "CVE-2012-0457",
                "CVE-2012-0455", "CVE-2012-0464", "CVE-2012-0456");
  script_bugtraq_id(52464, 52466, 52460, 52459, 52458, 52465, 52461);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-19 17:59:17 +0530 (Mon, 19 Mar 2012)");
  script_name("Mozilla Products Multiple Vulnerabilities - Mar12 (Mac OS X)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/48402");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-13.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-14.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-16.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-19.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = NULL;
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(!isnull(ffVer))
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"3.6.28") ||
     version_in_range(version:ffVer, test_version:"4.0", test_version2:"10.0.2"))
  {
    security_message(0);
    exit(0);
  }
}

# SeaMonkey Check
seaVer = NULL;
seaVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(!isnull(seaVer))
{
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.8"))
  {
    security_message(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = NULL;
tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(!isnull(tbVer))
{
  # Grep for Thunderbird version
  if(version_is_less(version:tbVer, test_version:"3.1.20") ||
     version_in_range(version:tbVer, test_version:"5.0", test_version2:"10.0.2")){
    security_message(0);
  }
}
