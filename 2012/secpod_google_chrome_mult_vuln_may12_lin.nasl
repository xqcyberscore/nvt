###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_may12_lin.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Google Chrome Multiple Vulnerabilities(02) - May 12 (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_affected = "Google Chrome version prior to 19.0.1084.52 on Linux";
tag_insight = "The flaws are due to
  - An unspecified error exists in the v8 garbage collection, plug-in
    JavaScript bindings.
  - A use-after-free error exists in the browser cache, first-letter handling
    and with encrypted PDF.
  - An out-of-bounds read error exists in Skia.
  - An error with websockets over SSL can be exploited to corrupt memory.
  - A bad cast error exists in the GTK UI.
  - An invalid read error exists in v8.
  - An invalid cast error exists with colorspace handling in PDF.
  - An error with PDF functions can be exploited to cause a buffer overflow.
  - A type corruption error exists in v8.";
tag_solution = "Upgrade to the Google Chrome 19.0.1084.52 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903031");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-3103", "CVE-2011-3104", "CVE-2011-3105", "CVE-2011-3106",
                "CVE-2011-3107", "CVE-2011-3108", "CVE-2011-3109", "CVE-2011-3110",
                "CVE-2011-3111", "CVE-2011-3112", "CVE-2011-3113", "CVE-2011-3114",
                "CVE-2011-3115");
  script_bugtraq_id(53679);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-25 16:25:17 +0530 (Fri, 25 May 2012)");
  script_name("Google Chrome Multiple Vulnerabilities(02) - May 12 (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49277/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027098");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/05/stable-channel-update_23.html");

  script_copyright("Copyright (C) 2012 SecPod");
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

## Variable Initialization
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Versions prior to 19.0.1084.52
if(version_is_less(version:chromeVer, test_version:"19.0.1084.52")){
  security_message(0);
}
