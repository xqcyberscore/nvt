###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_mult_vuln_feb12_win_01.nasl 7699 2017-11-08 12:10:34Z santu $
#
# Oracle Java SE JRE Multiple Vulnerabilities - February 2012 (Windows - 01)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors.
  Impact Level: System/Application";
tag_affected = "Oracle Java SE JRE 7 Update 2 and earlier, 6 Update 30 and earlier, 5.0 Update 33
  and earlier, and 1.4.2_35 and earlier";
tag_insight = "Multiple flaws are caused by unspecified errors in the following
  components:
  - 2D
  - AWT
  - Sound
  - I18n
  - CORBA
  - Serialization";
tag_solution = "Upgrade to Oracle Java SE JRE versions 7 Update 3, 6 Update 31, 5.0 Update
  34, 1.4.2_36 or later. For updates refer to
  http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html";
tag_summary = "This host is installed with Oracle Java SE JRE and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(802610);
  script_version("$Revision: 7699 $");
  script_cve_id("CVE-2011-3563", "CVE-2012-0499", "CVE-2012-0502",
                "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506");
  script_bugtraq_id(52011, 52012, 52014, 52016, 52017, 52018);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 13:10:34 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2012-02-21 16:16:16 +0530 (Tue, 21 Feb 2012)");
  script_name("Oracle Java SE JRE Multiple Vulnerabilities - February 2012 (Windows - 01)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48009");
  script_xref(name : "URL" , value : "http://www.pre-cert.de/advisories/PRE-SA-2012-01.txt");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/java/javase/documentation/overview-142120.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Variable Initialization
jreVer = "";

## Get JRE Version from KB
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{
  ## Check for Oracle Java SE JRE 7 Update 2 and earlier, 6 Update 30 and earlier,
  ## 5.0 Update 33 and earlier, and 1.4.2_35 and earlier
  if(version_is_less_equal(version:jreVer, test_version:"1.4.2.35") ||
     version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.2")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.30")||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.33"))
  {
    security_message(0);
    exit(0);
  }
}
