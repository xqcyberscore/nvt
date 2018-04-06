###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avg_antivirus_remote_code_exec_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# AVG Anti-Virus 'hcp://' Protocol Handler Remote Code Execution Vulnerability
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

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_impact = "Successful exploitation could allow the attackers to bypass virus
scanning and allows an attacker to drop and execute known malicious files.

Impact Level: Application";

tag_affected = "AVG Anti-Virus versions 8.0, 8.0.156 and 8.0.323";

tag_insight = "The flaw is due to an error in application when interacting
with the hcp:// URLs by the Microsoft Help and Support Center.";

tag_summary = "The host is installed with AVG Anti-Virus and is prone to remote
code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802976");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2010-3498");
  script_bugtraq_id(44189);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-10-01 18:51:18 +0530 (Mon, 01 Oct 2012)");
  script_name("AVG Anti-Virus 'hcp://' Protocol Handler Remote Code Execution Vulnerability");

  script_xref(name : "URL" , value : "http://www.n00bz.net/antivirus-cve");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/514356");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2010/Jun/205");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_avg_detect_win.nasl");
  script_mandatory_keys("AVG/AV/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
avVer = "";

## Get the version from KB
avVer = get_kb_item("AVG/AV/Win/Ver");
if(!avVer){
  exit(0);
}

## Check for AVG Anti-Virus 2013 and prior
if(version_is_equal(version:avVer, test_version:"8.0") ||
   version_is_equal(version:avVer, test_version:"8.5.323") ||
   version_is_equal(version:avVer, test_version:"8.0.156")){
  security_message(0);
}
