###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_avi_bof_vuln_lin.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# VLC Media Player '.AVI' File BOF Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  Impact Level: Application";
tag_affected = "VLC media player version prior to 1.1.11 on Linux.";
tag_insight = "The flaw is due to an integer underflow error when parsing the 'strf'
  chunk within AVI files can be exploited to cause a heap-based buffer
  overflow.";
tag_solution = "Upgrade to the VLC media player version 1.1.11 or later,
  For updates refer to http://www.videolan.org/";
tag_summary = "The host is installed with VLC Media Player and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902707");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)");
  script_cve_id("CVE-2011-2588");
  script_bugtraq_id(48664);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("VLC Media Player '.AVI' File BOF Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45066");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68532");
  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa1106.html");

  script_copyright("Copyright (c) 2011 SecPod");
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

## Check for VLC Media Player Version
if(version_is_less(version:vlcVer, test_version:"1.1.11")){
  security_message(0);
}
