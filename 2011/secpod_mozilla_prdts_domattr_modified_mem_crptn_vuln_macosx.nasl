###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_domattr_modified_mem_crptn_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Mozilla Products DOMAttrModified Memory Corruption Vulnerability (MAC OS X)
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
tag_affected = "SeaMonkey version 2.5
  Thunderbird version 8.0
  Mozilla Firefox version 8.0";
tag_insight = "The flaw is due to error in SVG implementation which results in an
  out-of-bounds memory access if SVG elements were removed during a
  DOMAttrModified event handler.";
tag_summary = "The host is installed with Mozilla firefox/thunderbird/seamonkey and is
  prone to out of bounds memory corruption vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902779");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3658");
  script_bugtraq_id(51138);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"creation_date", value:"2011-12-22 11:48:05 +0530 (Thu, 22 Dec 2011)");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_name("Mozilla Products DOMAttrModified Memory Corruption Vulnerability (MAC OS X)");

  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51138/info");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-55.html");

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
  if(version_is_equal(version:ffVer, test_version:"8.0"))
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
  if(version_is_equal(version:seaVer, test_version:"2.5"))
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
  if(version_is_equal(version:tbVer, test_version:"8.0")){
    security_message(0);
  }
}
