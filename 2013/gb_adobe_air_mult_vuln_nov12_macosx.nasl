###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln_nov12_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Adobe Air Multiple Vulnerabilities - November12 (Mac OS X)
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

tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the affected
  application.
  Impact Level: System/Application";
tag_affected = "Adobe AIR version 3.4.0.2710 and earlier on Mac OS X";
tag_insight = "Multiple unspecified errors exists due to memory corruption, buffer overflow
  that could lead to code execution.";
tag_solution = "Update to Adobe Air version 3.5.0.600 or later,
  For updates refer to http://get.adobe.com/air";
tag_summary = "This host is installed with Adobe Air and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803453");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2012-5274", "CVE-2012-5275", "CVE-2012-5276", "CVE-2012-5277",
                "CVE-2012-5278", "CVE-2012-5279", "CVE-2012-5280");
  script_bugtraq_id(56412);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-28 15:40:07 +0530 (Thu, 28 Mar 2013)");
  script_name("Adobe Air Multiple Vulnerabilities - November12 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51213");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-24.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Variable Initialization
airVer = "";

# Check for Adobe Air 3.4.0.2540 and prior
airVer = get_kb_item("Adobe/Air/MacOSX/Version");
if(airVer)
{
  # Grep for version 3.4.0.2540 and prior
  if(version_is_less_equal(version:airVer, test_version:"3.4.0.2710"))
  {
    security_message(0);
    exit(0);
  }
}
