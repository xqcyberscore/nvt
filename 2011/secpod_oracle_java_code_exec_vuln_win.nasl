###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_java_code_exec_vuln_win.nasl 7699 2017-11-08 12:10:34Z santu $
#
# Oracle Java SE Code Execution Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful attacks will allow attackers to execute arbitrary code in the
  context of the affected application with system privileges.
  Impact Level: Application";
tag_affected = "Oracle Java SE 6 Update 10 through 6 Update 23";
tag_insight = "The flaw is due to an error in 'Java Runtime Environment(JRE)', which
  allows remote untrusted Java Web Start applications and untrusted Java
  applets to affect confidentiality, integrity, and availability via unknown
  vectors related to deployment.";
tag_solution = "Upgrade to Oracle Java SE 6 Update 24 or later
  For updates refer to http://java.com/en/download/index.jsp";
tag_summary = "This host is installed with Sun Java SE and is prone to code
  execution vulnerability.";

if(description)
{
  script_id(902349);
  script_version("$Revision: 7699 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 13:10:34 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2010-4467");
  script_bugtraq_id(46395);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Oracle Java SE Code Execution Vulnerability (Windows)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0405");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpufeb2011-304611.html");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

# Get KB for JRE Version On Windows
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{

  # Check version from 1.6.0.10 to 1.6.0.23
  if(version_in_range(version:jreVer, test_version:"1.6.0.10", test_version2:"1.6.0.23"))
  {
    security_message(0);
    exit(0);
  }
}

# Get KB for JDK Version On Windows
jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  # Check version from 1.6.0.10 to 1.6.0.23
  if(version_in_range(version:jdkVer, test_version:"1.6.0.10", test_version2:"1.6.0.23")){  
    security_message(0);
  }
}
