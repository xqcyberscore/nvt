###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_use_after_free_vuln.nasl 8244 2017-12-25 07:29:28Z teissa $
#
# Adobe Shockwave Player Use-After-Free Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will let the user-assisted remote
attackers to execute arbitrary code via a crafted web site related to the
Shockwave Settings window and an unloaded library.

Impact Level: System/Application.";

tag_affected = "Adobe Shockwave Player Version 11.5.9.615 on Windows.";

tag_insight = "The flaw is due to a use-after-free error in an automatically
installed compatibility component.";

tag_solution = "Upgrade to Adobe Shockwave Player Version 11.5.9.620,
For updates refer to http://get.adobe.com/shockwave/otherversions/";

tag_summary = "This host is installed with Adobe Shockwave Player and is prone
to use-after-free vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801631");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-11-12 15:34:28 +0100 (Fri, 12 Nov 2010)");
  script_cve_id("CVE-2010-4092");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Shockwave Player Use-After-Free Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42112");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

## Check for Adobe Shockwave Player 11.5.9.615
if(version_is_equal(version:shockVer, test_version:"11.5.9.615")){
  security_message(0);
}
