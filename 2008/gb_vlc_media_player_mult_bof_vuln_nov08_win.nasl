###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_mult_bof_vuln_nov08_win.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# VLC Media Player Multiple Stack-Based BOF Vulnerabilities - Nov08 (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_solution = "Upgrade to 0.9.6, or
  Apply the available patch from below link,
  http://git.videolan.org/?p=vlc.git;a=commitdiff;h=e3cef651125701a2e33a8d75b815b3e39681a447
  http://git.videolan.org/?p=vlc.git;a=commitdiff;h=5f63f1562d43f32331006c2c1a61742de031b84d

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation allows attackers to execute arbitrary code
  within the context of the VLC media player by tricking a user into opening
  a specially crafted file or can even crash an affected application.
  Impact Level: Application";
tag_affected = "VLC media player 0.5.0 through 0.9.5 on Windows (Any).";
tag_insight = "The flaws are caused while parsing,
  - header of an invalid CUE image file related to modules/access/vcd/cdrom.c.
  - an invalid RealText(rt) subtitle file related to the ParseRealText function
    in modules/demux/subtitle.c.";
tag_summary = "This host is installed with VLC Media Player and is prone to
  Multiple Stack-Based Buffer Overflow Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800132");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-14 10:43:16 +0100 (Fri, 14 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5032", "CVE-2008-5036");
  script_bugtraq_id(32125);
  script_name("VLC Media Player Multiple Stack-Based BOF Vulnerabilities - Nov08 (Windows)");

  script_xref(name : "URL" , value : "http://www.videolan.org/security/sa0810.html");
  script_xref(name : "URL" , value : "http://www.trapkit.de/advisories/TKADV2008-011.txt");
  script_xref(name : "URL" , value : "http://www.trapkit.de/advisories/TKADV2008-012.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

vlcVer = registry_get_sz(item:"Version", key:"SOFTWARE\VideoLAN\VLC");
if(!vlcVer){
  exit(0);
}

# Check for VLC Media Player Version 0.5.0 to 0.9.5
if(version_in_range(version:vlcVer, test_version:"0.5.0", test_version2:"0.9.5")){
  security_message(0);
}
