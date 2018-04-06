###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_mult_vuln_win_feb12.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# RealNetworks RealPlayer Multiple Vulnerabilities (Windows) - Feb12
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary
  code.
  Impact Level: Application";
tag_affected = "RealPlayer versions 11.x and 14.x
  RealPlayer versions 15.x before 15.02.71
  RealPlayer SP versions 1.0 through 1.1.5 (12.0.0.879)";
tag_insight = "The flaws are due to
  - An unspecified error in rvrender.dll, which allows to execute arbitrary
    code via a crafted flags in an RMFF file.
  - Improper handling of the frame size array by the RV20 codec, which allows
    to execute arbitrary code via a crafted RV20 RealVideo video stream.
  - Unspecified errors when processing VIDOBJ_START_CODE segments and
    coded_frame_size value in RealAudio audio stream.
  - An unspecified error in the RV40 and RV10 codec, which allows to execute
    arbitrary code via a crafted RV40 or RV10 RealVideo video stream.";
tag_solution = "Upgrade to RealPlayer version 15.02.71 or later,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to multiple
  vulnerabilities";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802800");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0922", "CVE-2012-0923", "CVE-2012-0924", "CVE-2012-0925",
                "CVE-2012-0926", "CVE-2012-0927");
  script_bugtraq_id(51883, 51884, 51885, 51887, 51888, 51889);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-21 13:01:53 +0530 (Tue, 21 Feb 2012)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Windows) - Feb12");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47896/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026643");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/02062012_player/en/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_require_keys("RealPlayer/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

# Variable Initialization
rpVer = NULL;

#Get Version
rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

## Check for Realplayer version
# versions 14 comes has 12.0.1
if((rpVer =~ "^11\.*") || (rpVer =~ "^12\.0\.1\.*") ||
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.879") ||
   version_in_range(version:rpVer, test_version:"15.0.0", test_version2:"15.0.1.13")){
  security_message(0);
}
