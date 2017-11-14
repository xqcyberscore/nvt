###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_code_exec_vuln_win.nasl 7699 2017-11-08 12:10:34Z santu $
#
# Oracle Java SE Java Runtime Environment Code Execution Vulnerability - (Windows)
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

tag_impact = "Successful exploitation allows remote attackers to bypass the Java sandbox
  restriction and execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Oracle Java SE versions 7 Update 2 and earlier, 6 Update 30 and earlier,
  and 5.0 Update 33 and earlier";
tag_insight = "The 'AtomicReferenceArray' class implementation does not ensure that the
  array is of the Object[] type, which allows attackers to cause a denial of
  service (JVM crash) or bypass Java sandbox restrictions.";
tag_solution = "Apply the patch from below link
  http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html";
tag_summary = "This host is installed with Oracle Java SE and is prone to code
  execution vulnerability.";

if(description)
{
  script_id(802947);
  script_version("$Revision: 7699 $");
  script_cve_id("CVE-2012-0507");
  script_bugtraq_id(52161);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 13:10:34 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2012-08-22 15:52:21 +0530 (Wed, 22 Aug 2012)");
  script_name("Oracle Java SE Java Runtime Environment Code Execution Vulnerability - (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48589");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html");
  script_xref(name : "URL" , value : "http://www.metasploit.com/modules/exploit/multi/browser/java_atomicreferencearray");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_require_keys("Sun/Java/JRE/Win/Ver");
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
if(jreVer)
{
  ## Check for Oracle Java SE versions 7, 6 Update 27 and earlier,
  ## 5.0 Update 31 and earlier
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.2") ||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.30") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.33")){
    security_message(0);
  }
}
