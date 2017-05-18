###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mult_vuln_macosx_feb12.nasl 5963 2017-04-18 09:02:14Z teissa $
#
# Adobe Shockwave Player Multiple Vulnerabilities - Feb 2012 (MAC OS X)
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

tag_impact = "Successful exploitation will allow attackers to cause denial of service or
  execute arbitrary code by tricking a user into visiting a specially crafted
  web page.
  Impact Level: System/Application";
tag_affected = "Adobe Shockwave Player Versions 11.6.3.633 and prior on Mac OS X";
tag_insight = "The flaws are due to memory corruptions errors in Shockwave 3D Asset
  component when processing malformed file.";
tag_solution = "Upgrade to Adobe Shockwave Player version 11.6.4.634 or later,
  For updates refer to http://get.adobe.com/shockwave/otherversions/";
tag_summary = "This host is installed with Adobe Shockwave Player and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(802399);
  script_version("$Revision: 5963 $");
  script_cve_id("CVE-2012-0757", "CVE-2012-0759", "CVE-2012-0760", "CVE-2012-0761",
                "CVE-2012-0762", "CVE-2012-0763", "CVE-2012-0764", "CVE-2012-0766",
                "CVE-2012-0758");
  script_bugtraq_id(51999, 52006, 52000, 52001, 52002, 52003, 52004, 52005, 52007);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-18 11:02:14 +0200 (Tue, 18 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-02-17 13:34:43 +0530 (Fri, 17 Feb 2012)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities - Feb 2012 (MAC OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47932/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026675");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-02.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_detect_macosx.nasl");
  script_require_keys("Adobe/Shockwave/MacOSX/Version");
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

## Variables Initialization
shockVer = NULL;

shockVer = get_kb_item("Adobe/Shockwave/MacOSX/Version");
if(!shockVer){
  exit(0);
}

## Check for Adobe Shockwave Player versions prior to 11.6.4.634
if(version_is_less(version:shockVer, test_version:"11.6.4.634")){
  security_message(0);
}
