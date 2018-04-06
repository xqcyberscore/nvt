###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_location_hash_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Google Chrome 'location.hash' Denial Of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation lets the attacker cause memory or CPU consumption,
  resulting in Denial of Service condition.
  Impact Level: Application";
tag_affected = "Google Chrome version 1.0.154.48 and prior on Windows.";
tag_insight = "Error exists when application fails to handle JavaScript code with a long
  string value for the hash property aka 'location.hash'.";
tag_solution = "Upgrade to Google Chrome version 4.1.249.1064 or later.
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to Denial of
  Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900824");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2955");
  script_name("Google Chrome 'location.hash' Denial Of Service Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3424/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/506006/100/0/threaded");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

# Check for Google Chrome version <= 1.0.154.48
if(version_is_less_equal(version:chromeVer, test_version:"1.0.154.48")){
  security_message(0);
}
