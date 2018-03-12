###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_unspecified_vuln04_jul14_lin.nasl 9070 2018-03-09 12:37:39Z cfischer $
#
# Oracle Java SE JRE Unspecified Vulnerability-04 Jul 2014 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108425");
  script_version("$Revision: 9070 $");
  script_cve_id("CVE-2014-4247");
  script_bugtraq_id(68626);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-03-09 13:37:39 +0100 (Fri, 09 Mar 2018) $");
  script_tag(name:"creation_date", value:"2014-07-25 10:43:38 +0530 (Fri, 25 Jul 2014)");
  script_name("Oracle Java SE JRE Unspecified Vulnerability-04 Jul 2014 (Linux)");

  tag_summary = "This host is installed with Oracle Java SE JRE and is prone to some unspecified
vulnerability.";

  tag_vuldetect = "Get the installed version of Oracle Java SE JRE with the help of detect NVT
and check it is vulnerable or not.";

  tag_insight = "The flaw exists due to an error related to the JavaFX subcomponent";

  tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code.

Impact Level: System/Application.";

  tag_affected = "Oracle Java SE 8 update 5.0 and prior on Linux";

  tag_solution = "Apply the patch from below link,

http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/59501");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1030577");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!jreVer = get_app_version(cpe:CPE))
{
  CPE = "cpe:/a:sun:jre";
  if(!jreVer = get_app_version(cpe:CPE)){
    exit(0);
  }
}

if(jreVer =~ "^(1\.8)")
{
  if(version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.5"))
  {
    security_message(0);
    exit(0);
  }
}

exit(99);