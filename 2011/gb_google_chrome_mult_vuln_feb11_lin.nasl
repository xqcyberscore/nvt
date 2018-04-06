###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_feb11_lin.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Google Chrome multiple vulnerabilities - February 11(Linux)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code
  in the context of the browser or cause denial-of-service condition.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 9.0.597.84";
tag_insight = "The flaws are due to
  - Use-after-free error in image loading
  - Not properly restricting drag and drop operations
  - PDF event handler, which does not properly interact with print operations
  - Not properly handling a missing key in an extension
  - Not properly handling autofill profile merging
  - Browser crash with bad volume setting
  - Race condition in audio handling";
tag_solution = "Upgrade to the Google Chrome 9.0.597.84 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801740");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_cve_id("CVE-2011-0777", "CVE-2011-0778", "CVE-2011-0779",
                "CVE-2011-0780", "CVE-2011-0781", "CVE-2011-0783",
                "CVE-2011-0784");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - February 11(Linux)");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/02/stable-channel-update.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_require_keys("Google-Chrome/Linux/Ver");
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

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 9.0.597.84
if(version_is_less(version:chromeVer, test_version:"9.0.597.84")){
  security_message(0);
}
