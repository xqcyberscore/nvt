###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_shockwave_player_unspecified_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Adobe Shockwave Player Unspecified Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful attack could allow attackers to execute of arbitrary code.
  Impact Level: Application";
tag_affected = "Adobe Shockwave Player before 11.0.0.465 on Windows.";
tag_insight = "The flaw exists due to inadequate sanitisation while processing
  unknown vectors.";
tag_solution = "Upgrade to Adobe Flash Player 11.0.0.465
  http://get.adobe.com/shockwave";
tag_summary = "This host has Adobe Shockwave Player installed and is prone to
  unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900587");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2186");
  script_name("Adobe Shockwave Player Unspecified Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35544");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-08.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_require_keys("Adobe/ShockwavePlayer/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

# Grep for versions prior to 11.0.0.465
if(version_is_less(version:shockVer, test_version:"11.0.0.465")){
  security_message(0);
}
