###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realplayer_mult_vuln_nov11_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# RealNetworks RealPlayer Multiple Vulnerabilities Nov - 11 (Windows)
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes within
  the context of the application and can cause heap overflow or cause denial
  of service.
  Impact Level: Application";
tag_affected = "RealPlayer versions prior to 15.0.0";
tag_insight = "Multiple flaws are due to,
  - Unspecified errors in RV20, RV10, RV30, ATRC and AAC codec, allows
    attackers to execute arbitrary code via unspecified vectors.
  - An unspecified error related to RealVideo rendering, related to MP4 video
    dimensions can be exploited to corrupt memory.
  - An unspecified error exists when parsing of QCELP streams, MP4 headers,
    MP4 files and the channel within the Cook codec and MLTI chunk length
    within IVR files.
  - An unspecified error exists related to sample size when parsing RealAudio
    files.
  - An unspecified error exists when handling RTSP SETUP requests.";
tag_solution = "Upgrade to RealPlayer version 15.0.0 or later
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902762");
  script_version("$Revision: 9351 $");
  script_bugtraq_id(50741);
  script_cve_id("CVE-2011-4253", "CVE-2011-4252", "CVE-2011-4251", "CVE-2011-4250",
                "CVE-2011-4249", "CVE-2011-4248", "CVE-2011-4247", "CVE-2011-4246",
                "CVE-2011-4245", "CVE-2011-4244", "CVE-2011-4254", "CVE-2011-4255",
                "CVE-2011-4262", "CVE-2011-4261", "CVE-2011-4260", "CVE-2011-4259",
                "CVE-2011-4258", "CVE-2011-4257", "CVE-2011-4256");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-29 13:58:17 +0530 (Tue, 29 Nov 2011)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities Nov - 11 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46954/");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/11182011_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_require_keys("RealPlayer/Win/Ver");
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

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

# Real player versions < 15.0.0
if(version_is_less(version:rpVer, test_version:"15.0.0.198")){
  security_message(0);
}
