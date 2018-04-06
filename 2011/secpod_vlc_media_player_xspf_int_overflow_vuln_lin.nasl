###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_xspf_int_overflow_vuln_lin.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# VLC Media Player XSPF Playlist Integer Overflow Vulnerability (Linux)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application. Failed attacks will cause denial-of-service
  conditions.
  Impact Level: System/Application";
tag_affected = "VLC media player version 0.8.5 through 1.1.9";
tag_insight = "The flaw is due to an integer overflow in XSPF playlist file parser,
  which allows attackers to execute arbitrary code via unspecified vectors.";
tag_solution = "Upgrade to the VLC media player version 1.1.10 or later,
  For updates refer to http://download.videolan.org/pub/videolan/vlc/";
tag_summary = "The host is installed with VLC Media Player and is prone integer
  overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902604");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-2194");
  script_bugtraq_id(48171);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("VLC Media Player XSPF Playlist Integer Overflow Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa1104.html");

  script_copyright("Copyright (C) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_require_keys("VLCPlayer/Lin/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
vlcVer = get_kb_item("VLCPlayer/Lin/Ver");
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player Version less than 0.8.5 through 1.1.9
if(version_in_range(version:vlcVer, test_version:"0.8.5", test_version2:"1.1.9")){
  security_message(0);
}
