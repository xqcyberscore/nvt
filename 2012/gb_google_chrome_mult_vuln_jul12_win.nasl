###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_jul12_win.nasl 10133 2018-06-08 11:13:34Z asteins $
#
# Google Chrome Multiple Vulnerabilities - July 12 (Windows)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802880");
  script_version("$Revision: 10133 $");
  script_cve_id("CVE-2012-2815", "CVE-2012-2816", "CVE-2012-2817", "CVE-2012-2818",
                "CVE-2012-2819", "CVE-2012-2820", "CVE-2012-2821", "CVE-2012-2822",
                "CVE-2012-2823", "CVE-2012-2824", "CVE-2012-2825", "CVE-2012-2826",
                "CVE-2012-2828", "CVE-2012-2829", "CVE-2012-2830", "CVE-2012-2831",
                "CVE-2012-2832", "CVE-2012-2833", "CVE-2012-2834", "CVE-2012-2764");
  script_bugtraq_id(54203);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 13:13:34 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2012-07-04 14:54:30 +0530 (Wed, 04 Jul 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - July 12 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49724");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/06/stable-channel-update_26.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
  script_tag(name : "impact" , value : "Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.
  Impact Level: System/Application");
  script_tag(name : "affected" , value : "Google Chrome version prior to 20.0.1132.43 on Windows");
  script_tag(name : "insight" , value : "Refer to the reference links for more information on the vulnerabilities.");
  script_tag(name : "solution" , value : "Upgrade to the Google Chrome 20.0.1132.43 or later,
  For updates refer to http://www.google.com/chrome");
  script_tag(name : "summary" , value : "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"20.0.1132.43")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
