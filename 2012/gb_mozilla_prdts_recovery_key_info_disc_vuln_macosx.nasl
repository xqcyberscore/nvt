###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_recovery_key_info_disc_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Mozilla Products 'Firefox Recovery Key.html' Information Disclosure Vulnerability (MAC OS X)
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

tag_solution = "Upgrade to Mozilla Firefox version 10.0 or  later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.7 or later
  http://www.mozilla.org/projects/seamonkey/";

tag_impact = "Successful exploitation will let attackers to read a Firefox Sync key via
  standard filesystem operations and gain sensitive information.
  Impact Level: System/Application";
tag_affected = "SeaMonkey version prior to 2.7
  Mozilla Firefox version 4.x through 9.0";
tag_insight = "The flaw is due to setting weak permissions for Firefox Recovery
  Key.html, which might allow local users to read a Firefox Sync key via
  standard filesystem operations.";
tag_summary = "The host is installed with Mozilla firefox/seamonkey and is prone
  to information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802582");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-06 14:03:00 +0530 (Mon, 06 Feb 2012)");
  script_cve_id("CVE-2012-0450");
  script_bugtraq_id(51787);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Mozilla Products 'Firefox Recovery Key.html' Information Disclosure Vulnerability (MAC OS X)");

  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-09.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"9.0"))
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
  if(version_is_less(version:seaVer, test_version:"2.7")){
     security_message(0);
  }
}
