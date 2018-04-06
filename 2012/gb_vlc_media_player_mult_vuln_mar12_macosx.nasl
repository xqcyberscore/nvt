###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mult_vuln_mar12_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# VLC Media Player Multiple Vulnerabilities - Mar 12 (MAC OS X)
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

tag_impact = "Successful exploitation could allow attackers to cause a denial of service or
  possibly execute arbitrary code via crafted streams.
  Impact Level: System/Application";
tag_affected = "VLC media player version prior to 2.0.1 on MAC OS X";
tag_insight = "The flaws are due to multiple buffer overflow errors in the
  application, which allows remote attackers to execute arbitrary code via
  crafted MMS:// stream and Real RTSP streams.";
tag_solution = "Upgrade to VLC media player version 2.0.1 or later,
  For updates refer to http://www.videolan.org/vlc/";
tag_summary = "This host is installed with VLC Media Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802725");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1775", "CVE-2012-1776");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-21 11:52:20 +0530 (Wed, 21 Mar 2012)");
  script_name("VLC Media Player Multiple Vulnerabilities - Mar 12 (MAC OS X)");
  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa1201.html");
  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa1202.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_require_keys("VLC/Media/Player/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
vlcVer = "";

## Get the version from KB
vlcVer = get_kb_item("VLC/Media/Player/MacOSX/Version");
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player Version less than 2.0.1
if(version_is_less(version:vlcVer, test_version:"2.0.1")){
  security_message(0);
}
