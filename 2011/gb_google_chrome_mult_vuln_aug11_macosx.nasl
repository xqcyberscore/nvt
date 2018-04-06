###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_aug11_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - August11 (MacOSX)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions or cause a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 13.0.782.107 on MacOSX.";
tag_insight = "For more information on the vulnerabilities refer the below links.";
tag_solution = "Upgrade to the Google Chrome 13.0.782.107 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802319");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_cve_id("CVE-2011-2358", "CVE-2011-2359", "CVE-2011-2360", "CVE-2011-2361",
                "CVE-2011-2783", "CVE-2011-2784", "CVE-2011-2785", "CVE-2011-2786",
                "CVE-2011-2787", "CVE-2011-2788", "CVE-2011-2789", "CVE-2011-2790",
                "CVE-2011-2791", "CVE-2011-2792", "CVE-2011-2793", "CVE-2011-2794",
                "CVE-2011-2795", "CVE-2011-2796", "CVE-2011-2797", "CVE-2011-2798",
                "CVE-2011-2799", "CVE-2011-2800", "CVE-2011-2801", "CVE-2011-2802",
                "CVE-2011-2803", "CVE-2011-2804", "CVE-2011-2805", "CVE-2011-2818",
                "CVE-2011-2819");
  script_bugtraq_id(48960);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome Multiple Vulnerabilities - August11 (MacOSX)");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1025882");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/08/stable-channel-update.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 13.0.782.107
if(version_is_less(version:chromeVer, test_version:"13.0.782.107")){
  security_message(0);
}
