###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_wmp_int_overflow_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Windows Media Player MID File Integer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will lets attacker execute arbitrary codes in
  the context of the affected player and can cause denial of service.
  Impact Level: System/Application";
tag_affected = "Windows Media Player version 11.0.5721.5145 and prior.";
tag_insight = "This flaw is due to a boundary checking error while processing mid files
  in Windows Media Player application.";
tag_solution = "No solution or patch was made available for at least one year since
  disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.
  For updates refer to http://www.microsoft.com/windows/windowsmedia/default.mspx";
tag_summary = "The host is installed with Windows Media Player and is prone to
  integer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900336");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1331");
  script_name("Microsoft Windows Media Player MID File Integer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8445");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_mandatory_keys("Win/MediaPlayer/Ver");
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

exit(0); ##Plugin may results to Fp
wmplayerVer = get_kb_item("Win/MediaPlayer/Ver");
if(!wmplayerVer){
  exit(0);
}

# Check for Windows Media Player version 11.0.5721.5145 and prior
if(version_is_less_equal(version:wmplayerVer, test_version:"11.0.5721.5145")){
  security_message(0);
}
