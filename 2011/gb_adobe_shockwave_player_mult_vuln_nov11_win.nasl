###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mult_vuln_nov11_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Adobe Shockwave Player Multiple Vulnerabilities (Windows) - Nov 2011
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  to cause a denial of service.
  Impact Level: Application/System";
tag_affected = "Adobe Shockwave Player Versions prior to 11.6.3.633 on Windows.";
tag_insight = "Multiple flaws are due to an error in,
  - DIRAPI.dll and TextXtra.x32 when parsing Director file headers.
  - DIRAPI.dll when parsing rcsl chunks within Director files.";
tag_solution = "Upgrade to Adobe Shockwave Player version 11.6.3.633 or later,
  For updates refer to http://get.adobe.com/shockwave/otherversions/";
tag_summary = "This host is installed with Adobe Shockwave Player and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802508");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-2446", "CVE-2011-2447", "CVE-2011-2448", "CVE-2011-2449");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-10 12:17:59 +0530 (Thu, 10 Nov 2011)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities (Windows) - Nov 2011");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46667/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-27.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_require_keys("Adobe/ShockwavePlayer/Ver");
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

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

## Check for Adobe Shockwave Player versions prior to 11.6.3.633
if(version_is_less(version:shockVer, test_version:"11.6.3.633")){
  security_message(0);
}
