###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_aug10.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# Google Chrome multiple vulnerabilities - (Aug10)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  in the context of the browser, cause denial-of-service conditions, or disclose
  sensitive information.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 5.0.375.127 on Windows";
tag_insight = "The flaws are due to:
  - A memory corruption with 'Geolocation' support.
  - An error in supporting the 'Ruby' language.
  - An error in 'Omnibox' implementation, which fails to anticipate entry of
    passwords.
  - An Error in implementing the notifications feature, history feature.
  - A memory corruption in 'MIME' type handling.
  - An error in text-editing implementation, which fails to properly perform
    casts, which has unspecified impact and attack vectors.
  - A memory corruption error  when processing 'SVG' files, file dialogs.
  - An unspecified error in the 'Windows kernel', which has unknown impact and
    attack vectors.";
tag_solution = "Upgrade to Google Chrome version 5.0.375.127 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902096");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-26 15:28:03 +0200 (Thu, 26 Aug 2010)");
  script_cve_id("CVE-2010-3120", "CVE-2010-3119", "CVE-2010-3118", "CVE-2010-3117",
                "CVE-2010-3116", "CVE-2010-3115", "CVE-2010-3114", "CVE-2010-3113",
                "CVE-2010-3112", "CVE-2010-3111");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - (Aug10)");


  script_copyright("Copyright (C) 2010 SecPod");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/");
  script_xref(name : "URL" , value : "http://seclists.org/cert/2010/182");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/current/#google_releases_chrome_5_06");
  script_xref(name : "URL" , value : "http://www.nessus.org/plugins/index.php?view=single&id=48383");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 5.0.375.127
if(version_is_less(version:chromeVer, test_version:"5.0.375.127")){
  security_message(0);
}
