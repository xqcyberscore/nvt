###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_bof_vuln_jan13_macosx.nasl 3556 2016-06-20 08:00:00Z benallard $
#
# Adobe Air Buffer Overflow Vulnerability (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause denial of service condition.
  Impact Level: System/Application";

tag_affected = "Adobe AIR version 3.5.0.880 and earlier on on Mac OS X";
tag_insight = "An integer overflow error within 'flash.display.BitmapData()', which can be
  exploited to cause a heap-based buffer overflow.";
tag_solution = "Update to Adobe Air version 3.5.0.1060 or later,
  For updates refer to http://get.adobe.com/air";
tag_summary = "This host is installed with Adobe Air and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(803444);
  script_version("$Revision: 3556 $");
  script_cve_id("CVE-2013-0630");
  script_bugtraq_id(57184);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 10:00:00 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2013-03-21 13:16:05 +0530 (Thu, 21 Mar 2013)");
  script_name("Adobe Air Buffer Overflow Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51771");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027950");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-01.html");

  script_summary("Check for the version of Adobe Air on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
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

## Variable Initialization
airVer = "";

# Check for Adobe Air
airVer = get_kb_item("Adobe/Air/MacOSX/Version");
if(airVer)
{
  # Grep for version less than 3.5.0.1060
  if(version_is_less(version:airVer, test_version:"3.5.0.1060"))
  {
    security_message(0);
    exit(0);
  }
}
