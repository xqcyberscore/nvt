###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_mult_unspecified_vuln02_jul14.nasl 7699 2017-11-08 12:10:34Z santu $
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-02 Jul 2014 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804688");
  script_version("$Revision: 7699 $");
  script_cve_id("CVE-2014-4264", "CVE-2014-4266", "CVE-2014-4221", "CVE-2014-4220",
                "CVE-2014-4208", "CVE-2014-2490");
  script_bugtraq_id(68612, 68596, 68571, 68576, 68580, 68645);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 13:10:34 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2014-07-25 09:35:38 +0530 (Fri, 25 Jul 2014)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-02 Jul 2014 (Windows)");

  tag_summary =
"This host is installed with Oracle Java SE JRE and is prone to multiple
unspecified vulnerabilities.";

  tag_vuldetect =
"Get the installed version of Oracle Java SE JRE with the help of detect NVT
and check it is vulnerable or not.";

  tag_insight =
"Multiple unspecified flaws exists,
- An error in the Security subcomponent related to the Elliptic Curve (EC)
cryptography implementation.
- An error in the Serviceability subcomponent related to
share/native/sun/management/GcInfoBuilder.c
- An error in the Libraries subcomponent related to
share/classes/java/lang/invoke/MethodHandles.java
- An unspecified error related to the Deployment subcomponent.
- Two errors related to the Deployment subcomponent.
- A format string error in the Hotspot subcomponent within the EventMark
constructor and destructor in share/vm/utilities/events.cpp";

  tag_impact =
"Successful exploitation will allow remote attackers to update, insert, or
delete certain data, execute arbitrary code, conduct denial-of-service and
disclose sensitive information.

Impact Level: System/Application.";

  tag_affected =
"Oracle Java SE 7 update 60 and prior, and 8 update 5 and prior on Windows";

  tag_solution =
"Apply the patch from below link,
http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/59501");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1030577");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
jreVer = "";

## Get version
if(!jreVer = get_app_version(cpe:CPE))
{
  CPE = "cpe:/a:sun:jre";
  if(!jreVer = get_app_version(cpe:CPE)){
    exit(0);
  }
}

if(jreVer =~ "^(1\.(7|8))")
{
  ##Check for Oracle Java SE Versions
  if(version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.60")||
     version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.5"))
  {
    security_message(0);
    exit(0);
  }
}
