###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_seamonkey_websockets_dos_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Mozilla Seamonkey 'WebSockets' Denial of Service Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

tag_summary = "The host is installed with Mozilla Seamonkey and is prone to multiple
  vulnerabilities.";
tag_solution = "Upgrade to SeaMonkey version to 2.13.1 or later,
  http://www.mozilla.org/projects/seamonkey";
tag_insight = "Error in the WebSockets implementation, allows remote attackers to cause a
  denial of service.";
tag_affected = "SeaMonkey versions before 2.13.1 on Windows";

if(description)
{
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_oid("1.3.6.1.4.1.25623.1.0.803391");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2012-4191");
  script_bugtraq_id(55889);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-10-15 17:43:07 +0530 (Mon, 15 Oct 2012)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Mozilla Seamonkey 'WebSockets' Denial of Service Vulnerability (Windows)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/50856");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50935");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-88.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  exit(0);
}


include("version_func.inc");

# Variable Initialization
seaVer = "";

# SeaMonkey Check
seaVer = get_kb_item("Seamonkey/Win/Ver");
if(seaVer)
{
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.13.1"))
  {
    security_message(0);
    exit(0);
  }
}
