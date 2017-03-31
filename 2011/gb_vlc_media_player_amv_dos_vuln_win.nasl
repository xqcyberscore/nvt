###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_amv_dos_vuln_win.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# VLC Media Player 'AMV' Denial of Service Vulnerability (Windows)
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

tag_impact = "Successful exploitation could allow attackers to cause a denial
of service or possibly execute arbitrary code via a malformed AMV file.
Impact Level: System/Application";

tag_affected = "VLC media player version 1.1.9 and prior on Windows.";

tag_insight = "The flaw is due to error while handling 'sp5xdec.c' in the
Sunplus SP5X JPEG decoder in libavcodec, performs a write operation outside the
bounds of an unspecified array.";

tag_solution = "Upgrade to VLC media player version 1.1.10 or later,
For updates refer to http://www.videolan.org/vlc/";

tag_summary = "The host is installed with VLC Media Player and is prone to denial
of service vulnerability.";

if(description)
{
  script_id(802119);
  script_version("$Revision: 3117 $");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_cve_id("CVE-2011-1931");
  script_bugtraq_id(47602);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("VLC Media Player 'AMV' Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/517706");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=624339");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check for the version of VLC Media Player");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_require_keys("VLCPlayer/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
vlcVer = get_kb_item("VLCPlayer/Win/Ver");
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player Version less than 1.1.9
if(version_is_less_equal(version:vlcVer, test_version:"1.1.9")){
  security_message(0);
}
