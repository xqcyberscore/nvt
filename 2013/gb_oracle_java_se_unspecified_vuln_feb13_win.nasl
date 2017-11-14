###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_unspecified_vuln_feb13_win.nasl 7699 2017-11-08 12:10:34Z santu $
#
# Oracle Java SE Unspecified Vulnerability - Feb 13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary
code via unknown vectors.

Impact Level: System/Application";

tag_affected = "Oracle Java version 7 Update 11 on Windows";

tag_insight = "Unspecified vulnerability allows remote attackers to bypass Java
security sandbox via unknown vectors.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Oracle Java SE and is prone to
unspecified vulnerability.";

if(description)
{
  script_id(803306);
  script_version("$Revision: 7699 $");
  script_cve_id("CVE-2013-1490");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 13:10:34 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2013-02-06 10:54:26 +0530 (Wed, 06 Feb 2013)");
  script_name("Oracle Java SE Unspecified Vulnerability - Feb 13 (Windows)");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Jan/142");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2013-1490");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpufeb2013-1841061.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_require_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


## Variable Initialization
jreVer = "";

## Get JRE Version from KB
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer)
{
  ## Check for Oracle Java SE version 1.7.0_11
  if(jreVer == "1.7.0.11")
  {
    security_message(0);
    exit(0);
  }
}
