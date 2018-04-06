###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serenity_player_code_exec_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Serenity/Mplay Audio Player Code Execution Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_impact = "Successful exploitation could allow local/remote attackers to trick the user
  to access the crafted m3u playlist file, execute the crafted shellcode into the
  context of the affected system memory registers to take control of the machine
  running the affected application.
  Impact Level: System";
tag_affected = "Serenity/Mplay Audio Player 3.2.3.0 and prior on Windows.";
tag_insight = "There exists a stack overflow vulnerability within the 'MplayInputFile()'
  function in 'src/plgui.c' that fails to sanitize user input while the user
  crafts his/her own malicious playlist 'm3u' file.";
tag_solution = "No solution or patch was made available for at least one year since disclosure
  of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.
  For updates refer to http://malsmith.kyabram.biz/serenity";
tag_summary = "This host is installed with Serenity/Mplay Audio Player and is prone
  to code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800729");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4097");
  script_name("Serenity/Mplay Audio Player Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/product/27998");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0911-exploits/serenityaudio-overflow.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_serenity_player_detect.nasl");
  script_require_keys("Serenity/Audio/Player/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

if(appVer  = get_kb_item("Serenity/Audio/Player/Ver"))
{
  if(version_is_less_equal(version:appVer, test_version:"3.2.3.0")){
    security_message(0);
  }
}

else if(appVer2 = get_kb_item("Mplay/Audio/Player/Ver"))
{
  if(version_is_less_equal(version:appVer2, test_version:"3.2.3.0")){
    security_message(0);
  }
}
