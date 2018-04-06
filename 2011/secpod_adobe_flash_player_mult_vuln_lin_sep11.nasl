###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_flash_player_mult_vuln_lin_sep11.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities September-2011 (Linux)
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

tag_impact = "Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service.
  Impact Level: iSystem/Application";
tag_affected = "Adobe Flash Player versions prior to 10.3.183.10 on Linux.";
tag_insight = "The flaws are due to
  - Stack-based buffer overflow in the ActionScript Virtual Machine (AVM)
    component, allows remote attackers to execute arbitrary code via
    unspecified vectors.
  - security control bypass, allows attackers to bypass intended access
    restrictions and obtain sensitive information via unspecified vectors
  - logic error vulnerability, allows remote attackers to cause a denial of
    service (browser crash) via unspecified vectors or execute arbitrary via
    crafted streaming media.
  - Cross-site scripting (XSS) vulnerability, allows remote attackers to
    inject arbitrary web script or HTML via a crafted URL.";
tag_solution = "Upgrade to Adobe Flash Player version 10.3.183.10 or later.
  For details refer, http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902739");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_cve_id("CVE-2011-2426", "CVE-2011-2427", "CVE-2011-2428",
                "CVE-2011-2429", "CVE-2011-2430", "CVE-2011-2444");
  script_bugtraq_id(49714, 49715, 49716, 49718, 49717, 49710);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player Multiple Vulnerabilities September-2011 (Linux)");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-26.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Get the version from KB
flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!flashVer){
  exit(0);
}

flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");

## Check for Adobe Flash Player versions prior to 10.3.183.10
if(version_is_less(version:flashVer, test_version:"10.3.183.10")){
  security_message(0);
}
