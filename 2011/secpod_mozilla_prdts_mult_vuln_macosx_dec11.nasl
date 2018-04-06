###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_mult_vuln_macosx_dec11.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Mozilla Products Multiple Vulnerabilities - Dec 11 (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_solution = "Upgrade to Mozilla Firefox version 9.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.6 or later
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 9.0 or later
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will likely
  result in denial-of-service conditions.
  Impact Level: Application";
tag_affected = "SeaMonkey version before 2.6
  Thunderbird version 5.0 through 8.0
  Mozilla Firefox version Firefox 4.x through 8.0";
tag_insight = "Multiple flaws are due to
  - Unspecified errors in browser engine.
  - An error exists within the YARR regular expression library when parsing
    javascript content.
  - Not properly handling SVG animation accessKey events when JavaScript is
    disabled. This can lead to the user's key strokes being leaked.
  - An error exists within the handling of OGG <video> elements.";
tag_summary = "The host is installed with Mozilla firefox/thunderbird/seamonkey and is
  prone multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902778");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665");
  script_bugtraq_id(51133, 51135, 51136, 51134);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"creation_date", value:"2011-12-22 12:14:45 +0530 (Thu, 22 Dec 2011)");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_name("Mozilla Products Multiple Vulnerabilities - Dec 11 (MAC OS X)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/47302/");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-53.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-54.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-56.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-58.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
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
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(ffVer)
{
  # Grep for Firefox version
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"8.0"))
  {
    security_message(0);
    exit(0);
  }
}

# SeaMonkey Check
seaVer = get_kb_item("SeaMonkey/MacOSX/Version");
if(seaVer)
{
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.6"))
  {
    security_message(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("ThunderBird/MacOSX/Version");
if(tbVer != NULL)
{
  # Grep for Thunderbird version
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"8.0")){
    security_message(0);
  }
}
