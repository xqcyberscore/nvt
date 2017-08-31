###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_media_player_dos_vuln_apr14.nasl 6724 2017-07-14 09:57:17Z teissa $
#
# Microsoft Windows Media Player '.wav' File Memory Corruption Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:windows_media_player";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804532";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6724 $");
  script_cve_id("CVE-2014-2671");
  script_bugtraq_id(66403);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-14 11:57:17 +0200 (Fri, 14 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-04 16:03:11 +0530 (Fri, 04 Apr 2014)");
  script_name("Microsoft Windows Media Player '.wav' File Memory Corruption Vulnerability");

  tag_summary =
"This host is installed with Microsoft Windows Media Player and is prone to
memorry corruption vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to improper handling of '.wav' files.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code or
cause a denial of service.

Impact Level: System/Application";

  tag_affected =
"Microsoft Windows Media Player 11.0.5721.5230";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/92080");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/32477");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125834");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_mandatory_keys("Win/MediaPlayer/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
mpVer = "";

## Get version
if(!mpVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

# Check for vulnerable version
if(version_is_equal(version:mpVer, test_version:"11.0.5721.5230"))
{
  security_message(0);
  exit(0);
}
