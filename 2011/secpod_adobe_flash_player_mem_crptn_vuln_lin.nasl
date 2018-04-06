###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_flash_player_mem_crptn_vuln_lin.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Adobe Flash Player Remote Memory Corruption Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service.
  Impact Level: Application/System";
tag_affected = "Adobe Flash Player version 10.2.152.33 and prior on Linux.";
tag_insight = "The flaw is due to an error when handling the 'SWF' file, which allows
  attackers to execute arbitrary code or cause a denial of service via crafted
  flash content.";
tag_solution = "Upgrade to Adobe Flash Player version 10.2.153.1 or later.
  For details refer, http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  memory corruption vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902401");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_cve_id("CVE-2011-0609");
  script_bugtraq_id(46860);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player Remote Memory Corruption Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-06.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa11-01.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_require_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!flashVer){
  exit(0);
}

flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");

## Check for Adobe Flash Player versions 10.2.152.33 and prior.
if(version_is_less_equal(version:flashVer, test_version:"10.2.152.33")){
  security_message(0);
}
