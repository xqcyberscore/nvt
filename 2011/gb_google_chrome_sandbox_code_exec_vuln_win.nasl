###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_sandbox_code_exec_vuln_win.nasl 3103 2016-04-18 14:50:34Z benallard $
#
# Google Chrome 'Sandbox' Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary
code in the context of the user running the application. Failed attacks may
cause denial-of-service conditions.

Impact Level: System/Application";

tag_affected = "Google Chrome version 11.0.696.65 and prior.";

tag_insight = "The flaw is due to an error in application, which bypasses all
security features including 'ASLR/DEP/Sandbox'.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed Google Chrome and is prone to remote code
execution vulnerability.";

if(description)
{
  script_id(801789);
  script_version("$Revision: 3103 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-18 16:50:34 +0200 (Mon, 18 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_cve_id("CVE-2011-2075");
  script_bugtraq_id(47771);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome 'Sandbox' Remote Code Execution Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.youtube.com/watch?v=c8cQ0yU89sk");
  script_xref(name : "URL" , value : "http://www.vupen.com/demos/VUPEN_Pwning_Chrome.php");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than or equal to 11.0.696.65
if(version_is_less(version:chromeVer, test_version:"11.0.696.65")){
  security_message(0);
}
