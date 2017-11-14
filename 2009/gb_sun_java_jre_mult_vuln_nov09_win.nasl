###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_jre_mult_vuln_nov09_win.nasl 7699 2017-11-08 12:10:34Z santu $
#
# Sun Java JDK/JRE Multiple Vulnerabilities - Nov09 (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation allows remote attacker to execute arbitrary code,
  gain escalated privileges, bypass security restrictions and cause denial
  of service attacks inside the context of the affected system.
  Impact Level: System/Application.";
tag_affected = "Sun Java JDK/JRE 6 prior to 6 Update 17
  Sun Java JDK/JRE 5 prior to 5 Update 22
  Sun Java JDK/JRE 1.4.x prior to 1.4.2_24
  Sun Java JDK/JRE 1.3.x prior to 1.3.1_27 on Windows.";
tag_insight = "Multiple flaws occur due to,
  - Error when decoding 'DER' encoded data and parsing HTTP headers.
  - Error when verifying 'HMAC' digests.
  - Integer overflow error in the 'JPEG JFIF' Decoder while processing
    malicious image files.
  - A buffer overflow error in the 'setDiffICM()' and 'setBytePixels()'
    functions in the Abstract Window Toolkit (AWT).
  - Unspecified error due to improper parsing of color profiles of images.
  - A buffer overflow error due to improper implementation of the
    'HsbParser.getSoundBank()' function.
  - Three unspecified errors when processing audio or image files.";
tag_solution = "Upgrade to JDK/JRE version 6 Update 17 or later.
  http://java.sun.com/javase/downloads/index.jsp
  OR
  Upgrade to JDK/JRE version 5 Update 22
  http://java.sun.com/javase/downloads/index_jdk5.jsp
  OR
  Upgrade to JDK/JRE version 1.4.2_24
  http://java.sun.com/j2se/1.4.2/download.html
  OR
  Upgrade to JDK/JRE version 1.3.1_27
  http://java.sun.com/j2se/1.3/download.html";
tag_summary = "This host is installed with Sun Java JDK/JRE and is prone to
  Multiple Vulnerabilities.";

if(description)
{
  script_id(800972);
  script_version("$Revision: 7699 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 13:10:34 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-11-13 15:48:12 +0100 (Fri, 13 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3877", "CVE-2009-3876", "CVE-2009-3875", "CVE-2009-3873",
                "CVE-2009-3874", "CVE-2009-3872", "CVE-2009-3871", "CVE-2009-3869",
                "CVE-2009-3868", "CVE-2009-3867");
  script_bugtraq_id(36881);
  script_name("Sun Java JDK/JRE Multiple Vulnerabilities - Nov09 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37231");
  script_xref(name : "URL" , value : "http://java.sun.com/javase/6/webnotes/6u17.html");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3131");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

i = 0;
if(jreVer = get_kb_item("Sun/Java/JRE/Win/Ver")) {
   version[i] = jreVer;
   i++;
}

if(jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver")) {
   version[i] = jdkVer;
}

foreach ver (version)
{
  if(ver)
  {
    # Check for 1.3 < 1.3.1_27, 1.4 < 1.4.2_24, 1.5 < 1.5.0_22 (5 Update 22),
    #       and 1.6 < 1.6.0_17 (6 Update 17)
    if(version_in_range(version:ver, test_version:"1.3", test_version2:"1.3.1.26")||
       version_in_range(version:ver, test_version:"1.4", test_version2:"1.4.2.23")||
       version_in_range(version:ver, test_version:"1.5", test_version2:"1.5.0.21")||
       version_in_range(version:ver, test_version:"1.6", test_version2:"1.6.0.16"))
    {
      security_message(0);
      exit(0);
    }
  }
}
