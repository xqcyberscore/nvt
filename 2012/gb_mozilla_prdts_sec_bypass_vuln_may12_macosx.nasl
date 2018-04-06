###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_sec_bypass_vuln_may12_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Mozilla Products Security Bypass Vulnerability - May12 (Mac OS X)
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

tag_solution = "Upgrade to Mozilla Firefox version 12.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.9 or later,
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 12.0 or later,
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation could allow attackers to inject scripts or bypass
  certain security restrictions.
  Impact Level: Application";
tag_affected = "SeaMonkey version before 2.9
  Thunderbird version 5.0 through 11.0
  Mozilla Firefox version 4.x through 11.0";
tag_insight = "The flaw is due to an error within the handling of XMLHttpRequest
  and WebSocket while using an IPv6 address can be exploited to bypass the
  same origin policy.";
tag_summary = "This host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to security bypass vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802843");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0475");
  script_bugtraq_id(53230);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-02 12:29:17 +0530 (Wed, 02 May 2012)");
  script_name("Mozilla Products Security Bypass Vulnerability - May12 (Mac OS X)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/48972/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48932/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026971");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-28.html");

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
ffVer = "";
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(!isnull(ffVer))
{
  # Grep for Firefox version
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"11.0"))
  {
    security_message(0);
    exit(0);
  }
}

# SeaMonkey Check
seaVer = "";
seaVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(!isnull(seaVer))
{
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.9"))
  {
    security_message(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = "";
tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(!isnull(tbVer))
{
  # Grep for Thunderbird version
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"11.0")){
    security_message(0);
  }
}
