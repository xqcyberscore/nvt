###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_mar11_lin.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Google Chrome multiple vulnerabilities - March 11 (Linux)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code
  in the context of the browser, perform spoofing attacks, or cause denial of
  service condition.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 9.0.597.107 on Linux";
tag_insight = "- An unspecified error related to the URL bar can be exploited to conduct
    spoofing attacks.
  - An unspecified error exists in the handling of JavaScript dialogs.
  - An error when handling stylesheet nodes can lead to a stale pointer.
  - An error when handling key frame rules can lead to a stale pointer.
  - An unspecified error exists in the handling of form controls.
  - An unspecified error exists while rendering SVG content.
  - An unspecified error in table handling can lead to a stale node.
  - An unspecified error in table rendering can lead to a stale pointer.
  - An unspecified error in SVG animations can lead to a stale pointer.
  - An unspecified error when handling XHTML can lead to a stale node.
  - An unspecified error exists in the textarea handling.
  - An unspecified error when handling device orientation can lead to a stale
    pointer.
  - An unspecified error in WebGL can be exploited to cause out-of-bounds reads.
  - An integer overflow exists in the textarea handling.
  - An unspecified error in WebGL can be exploited to cause out-of-bounds reads.
  - An unspecified error can lead to exposure of internal extension functions.
  - A use-after-free error exists within the handling of blocked plug-ins.
  - An unspecified error when handling layouts can lead to a stale pointer.";
tag_solution = "Upgrade to the Google Chrome 9.0.597.107 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801856");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_bugtraq_id(46614);
  script_cve_id("CVE-2011-1107", "CVE-2011-1108", "CVE-2011-1109", "CVE-2011-1110",
                "CVE-2011-1111", "CVE-2011-1112", "CVE-2011-1114", "CVE-2011-1115",
                "CVE-2011-1116", "CVE-2011-1117", "CVE-2011-1118", "CVE-2011-1119",
                "CVE-2011-1120", "CVE-2011-1121", "CVE-2011-1122", "CVE-2011-1123",
                "CVE-2011-1124", "CVE-2011-1125");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome multiple vulnerabilities - March 11 (Linux)");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/02/stable-channel-update_28.html");

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

## Check for Google Chrome Version less than 9.0.597.107
if(version_is_less(version:chromeVer, test_version:"9.0.597.107")){
  security_message(0);
}
