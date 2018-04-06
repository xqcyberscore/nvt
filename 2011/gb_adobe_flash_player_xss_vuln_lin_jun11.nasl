###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_xss_vuln_lin_jun11.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Adobe Flash Player Unspecified Cross-Site Scripting Vulnerability June-2011 (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site.
  Impact Level: Application/System";
tag_affected = "Adobe Flash Player versions before 10.3.181.22 on Linux.";
tag_insight = "The flaw is caused by improper validation of certain unspecified input,
  which allows remote attackers to inject arbitrary web script or HTML via
  unspecified vectors.";
tag_solution = "Upgrade to Adobe Flash Player version 10.3.181.22 or later.
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  cross-site scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802205");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-2107");
  script_bugtraq_id(48107);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Adobe Flash Player Unspecified Cross-Site Scripting Vulnerability June-2011 (Linux)");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-13.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_require_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!flashVer){
  exit(0);
}

flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");

## Check for Adobe Flash Player versions prior to 10.3.181.22
if(version_is_less(version:flashVer, test_version:"10.3.181.22")){
  security_message(0);
}
