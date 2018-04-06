###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_may12_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - May 12 (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to bypass certain security
  restrictions,  execute arbitrary code in the context of the browser or
  cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 19.0.1084.46 on Mac OS X";
tag_insight = "Refer to the reference links for more information on the vulnerabilities.";
tag_solution = "Upgrade to the Google Chrome 19.0.1084.46 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802793");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-3100", "CVE-2011-3084", "CVE-2011-3099", "CVE-2011-3083",
                "CVE-2011-3097", "CVE-2011-3095", "CVE-2011-3094", "CVE-2011-3093",
                "CVE-2011-3092", "CVE-2011-3091", "CVE-2011-3090", "CVE-2011-3089",
                "CVE-2011-3088", "CVE-2011-3087", "CVE-2011-3086", "CVE-2011-3085",
                "CVE-2011-3102");
  script_bugtraq_id(53540);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-17 12:28:09 +0530 (Thu, 17 May 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - May 12 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49194/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027067");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/05/stable-channel-update.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_require_keys("GoogleChrome/MacOSX/Version");
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

## Variable Initialization
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Versions prior to 19.0.1084.46
if(version_is_less(version:chromeVer, test_version:"19.0.1084.46")){
  security_message(0);
}
