###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_demuxer_double_free_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# VLC Media Player TiVo Demuxer Double Free Vulnerability (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow an attacker to crash an affected
  application and denying service to legitimate users.
  Impact Level: Application";
tag_affected = "VLC media player version 0.9.0 to 1.1.12 on Mac OS X";
tag_insight = "The flaw is due to a double-free error within the 'get_chunk_header()'
  function in 'modules/demux/ty.c' of the TiVo demuxer when opening a specially
  crafted TiVo (*.ty) file.";
tag_solution = "Upgrade VLC media player to 1.1.13 or later,
  For updates refer to http://www.videolan.org/vlc/";
tag_summary = "This host is installed with VLC Media Player and is prone to
  double free vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802487");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0023", "CVE-2011-5231");
  script_bugtraq_id(51147, 51231);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-11-02 12:41:07 +0530 (Fri, 02 Nov 2012)");
  script_name("VLC Media Player TiVo Demuxer Double Free Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47325");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1026449");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71916");
  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa1108.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
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

## Check for VLC Media Player Version is in range 0.9.0 through 1.1.12
if(version_in_range(version:vlcVer, test_version:"0.9.0", test_version2:"1.1.12")){
  security_message(0);
}
