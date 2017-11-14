###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_mult_vuln03_may13_win.nasl 7699 2017-11-08 12:10:34Z santu $
#
# Oracle Java SE Multiple Vulnerabilities -03 May 13 (Windows)
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

tag_impact = "Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors. Attackers can even execute
  arbitrary code on the target system.
  Impact Level: System/Application";

tag_affected = "Oracle Java SE Version 7 Update 17 and earlier";
tag_insight = "Multiple flaws due to unspecified errors in the JavaFX, Libraries,
  HotSpot, Install, Deployment and JAX-WX components.";
tag_solution = "Apply patch from below link,
  http://www.oracle.com/technetwork/topics/security/javacpuapr2013-1928497.html";
tag_summary = "This host is installed with Oracle Java SE and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803488);
  script_version("$Revision: 7699 $");
  script_cve_id("CVE-2013-2438", "CVE-2013-2436", "CVE-2013-2431",
                "CVE-2013-2426", "CVE-2013-2425", "CVE-2013-2423",
                "CVE-2013-2421", "CVE-2013-2416", "CVE-2013-2415",
                "CVE-2013-2434", "CVE-2013-2428", "CVE-2013-2427",
                "CVE-2013-2414", "CVE-2013-1564", "CVE-2013-1561");
  script_bugtraq_id(59185, 59213, 59165, 59206, 59191,
                    59162, 59153, 59088, 59212, 59137,
                    59175, 59128, 59234, 59195, 59203);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 13:10:34 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2013-05-06 17:27:22 +0530 (Mon, 06 May 2013)");
  script_name("Oracle Java SE Multiple Vulnerabilities -03 May 13 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53008");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpuapr2013-1928497.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpuapr2013verbose-1928687.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
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

## Variable Initialization
jreVer = "";

## Get JRE Version from KB
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer && jreVer =~ "^(1\.7)")
{
  ##Check for Oracle Java SE Versions
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.17"))
  {
    security_message(0);
    exit(0);
  }
}
