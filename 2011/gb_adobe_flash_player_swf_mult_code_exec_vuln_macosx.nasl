###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_swf_mult_code_exec_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Adobe Flash Player 'SWF' File Multiple Code Execution Vulnerability - Mac OS X
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

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary code in the context of the affected application.

Impact Level: System/Application";

tag_affected = "Adobe Flash Player version 11.1.102.55 on MAC OS X";

tag_insight = "The flaws are due to an unspecified error in the application,
allows remote attackers to execute arbitrary code via a crafted SWF file.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Adobe Flash Player and is prone to
multiple arbitrary code execution vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802541");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-4694", "CVE-2011-4693");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-09 11:41:37 +0530 (Fri, 09 Dec 2011)");
  script_name("Adobe Flash Player 'SWF' File Multiple Code Execution Vulnerability - Mac OS X");
  script_xref(name : "URL" , value : "http://partners.immunityinc.com/movies/VulnDisco-Flash0day-v2.mov");
  script_xref(name : "URL" , value : "https://lists.immunityinc.com/pipermail/dailydave/2011-December/000402.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_require_keys("Adobe/Flash/Player/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

# Check for Adobe Flash Player
playerVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(playerVer != NULL)
{
  if(version_is_equal(version:playerVer, test_version:"11.1.102.55")){
    security_message(0);
  }
}
