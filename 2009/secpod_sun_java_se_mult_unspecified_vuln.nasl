###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_se_mult_unspecified_vuln.nasl 7699 2017-11-08 12:10:34Z santu $
#
# Sun Java SE Multiple Unspecified Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_solution = "Upgrade to Java SE version 5 Update 20
  http://java.sun.com/javase/downloads/index_jdk5.jsp
  or
  Apply the patch from below link,
  http://sunsolve.sun.com/search/document.do?assetkey=1-21-118667-22-1

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Impact is unknown.

  Impact Level: System/Application";
tag_affected = "Sun Java SE version 5.0 before Update 20";
tag_insight = "Refer to the SunSolve bugId 6406003/6429594/6444262 for more information.";
tag_summary = "This host is installed with Sun Java SE and is prone to multiple
  unspecified vulnerabilities.";

if(description)
{
  script_id(900819);
  script_version("$Revision: 7699 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 13:10:34 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-08-24 07:49:31 +0200 (Mon, 24 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2721", "CVE-2009-2722", "CVE-2009-2723",
                "CVE-2009-2724");
  script_name("Sun Java SE Multiple Unspecified Vulnerabilities");

  script_xref(name : "URL" , value : "http://java.sun.com/j2se/1.5.0/ReleaseNotes.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl", "gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win_or_Linux/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

# Get KB for JDK Version On Windows
jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");

if(jdkVer)
{
  # Check for 1.5 < 1.5.0_20 (5 Update 20)
  if(version_in_range(version:jdkVer, test_version:"1.5", test_version2:"1.5.0.19"))
  {
    security_message(0);
    exit(0);
  }
}

# Get KB for JRE Version On Windows
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(isnull(jreVer))
{
  # Get KB for JRE/JDK Version On Linux
  jreVer = get_kb_item("Sun/Java/JRE/Linux/Ver");

  if(isnull(jreVer))
    exit(0);
}

if(jreVer)
{
  # Check for 1.5 < 1.5.0_20 (5 Update 20)
  if(version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.19")){
    security_message(0);
  }
}
