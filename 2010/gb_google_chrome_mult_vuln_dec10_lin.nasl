###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_dec10_lin.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Google Chrome multiple vulnerabilities - Dec 10(Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to cause a denial of service.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 8.0.552.224 on Linux";
tag_insight = "- The ThemeInstalledInfoBarDelegate::Observe function in browser/extensions/
    theme_installed_infobar_delegate.cc does not properly handle incorrect tab
    interaction by an extension.
  - browser/worker_host/message_port_dispatcher.cc does not properly handle
    certain postMessage calls, which allows remote attackers to cause a denial
    of service via crafted JavaScript code that creates a web worker.
  - Out-of-bounds read error in CSS parsing allows remote attackers to cause a
    denial of service.
  - Stale pointers in cursor handling allows remote attackers to cause a denial
    of service.";
tag_solution = "Upgrade to the Google Chrome 8.0.552.224 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801668");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-4575", "CVE-2010-4576", "CVE-2010-4577",
                "CVE-2010-4578");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome multiple vulnerabilities - Dec 10(Linux)");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=60761");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=63529");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=63866");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=64959");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2010/12/stable-beta-channel-updates_13.html");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

## Check for Google Chrome Version less than 8.0.552.224
if(version_is_less(version:chromeVer, test_version:"8.0.552.224")){
  security_message(0);
}
