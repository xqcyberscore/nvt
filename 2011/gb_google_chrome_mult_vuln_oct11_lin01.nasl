###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_oct11_lin01.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Google Chrome multiple vulnerabilities - October11 (Linux)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code,
  steal cookie-based authentication credentials, bypass the cross-origin
  restrictions, perform spoofing attacks, and disclose potentially sensitive
  information, other attacks may also be possible.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 15.0.874.102 on Linux";
tag_insight = "For more details about the vulnerabilities refer the reference section.";
tag_solution = "Upgrade to the Google Chrome 15.0.874.102 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802263");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");
  script_cve_id("CVE-2011-2845", "CVE-2011-3875", "CVE-2011-3876", "CVE-2011-3877",
                "CVE-2011-3878", "CVE-2011-3879", "CVE-2011-3880", "CVE-2011-3881",
                "CVE-2011-3882", "CVE-2011-3883", "CVE-2011-3884", "CVE-2011-3885",
                "CVE-2011-3886", "CVE-2011-3887", "CVE-2011-3888", "CVE-2011-3889",
                "CVE-2011-3890", "CVE-2011-3891");
  script_bugtraq_id(50360);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome multiple vulnerabilities - October11 (Linux)");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026242");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/10/chrome-stable-release.html");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_require_keys("Google-Chrome/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 15.0.874.102
if(version_is_less(version:chromeVer, test_version:"15.0.874.102")){
  security_message(0);
}
