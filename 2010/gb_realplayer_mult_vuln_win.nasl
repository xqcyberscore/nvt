###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_mult_vuln_win.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# RealNetworks RealPlayer Multiple Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let the attacker execute arbitrary
  codes within the context of the application and can cause heap overflow
  or allow remote code execution.";
tag_affected = "RealPlayer SP 1.0 to 1.1.4 (12.x)
  RealNetworks RealPlayer SP 11.0 to 11.1 on Windows platform.";
tag_insight = "The multiple flaws are due to,
  - An error in the handling of dimensions during 'YUV420'
    transformations, which allows attackers to execute arbitrary code via
    crafted MP4 content.
  - An integer overflow error in the handling of crafted QCP file.
  - A heap-based buffer overflow when handling large size values in 'QCP'
    audio content.
  - An integer overflows in the 'ParseKnownType()' function, which allows
    attackers to execute arbitrary code via crafted 'HX_FLV_META_AMF_TYPE_MIXEDARRAY'
    or 'HX_FLV_META_AMF_TYPE_ARRAY' data in an FLV file.
  - An unspecified error in an ActiveX control in the Internet Explorer (IE)
    plugin, has unknown impact and attack vectors related to
    'multiple browser windows.'";
tag_solution = "Upgrade to RealPlayer SP version 1.1.5,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801507");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
  script_bugtraq_id(42775);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0117", "CVE-2010-0116", "CVE-2010-0120",
                "CVE-2010-3000", "CVE-2010-3001");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-5/");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/08262010_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

## Realplayer version 11.x, 1.x(12.x)
if(version_in_range(version:rpVer, test_version:"11.0.0", test_version2:"11.0.0.674") ||
   version_in_range(version:rpVer, test_version:"12.0.0", test_version2:"12.0.0.873")){
  security_message(0);
}

