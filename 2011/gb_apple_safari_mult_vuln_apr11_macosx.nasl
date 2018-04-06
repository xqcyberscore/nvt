###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_apr11_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apple Safari Multiple Vulnerabilities - April 2011 (Mac OS X)
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the browser.
  Impact Level: System/Application";
tag_affected = "Apple Safari versions prior to 5.0.5";
tag_insight = "Multiple flaws are due to
  - An integer overflow error in WebKit related to CSS 'style handling',
    nodesets, and a length value.
  - A use-after-free error within WebKit when handling WBR tags.";
tag_solution = "Upgrade to Apple Safari version 5.0.5 or later,
  For updates refer to http://www.apple.com/safari/download/";
tag_summary = "The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802234");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_cve_id("CVE-2011-1290", "CVE-2011-1344");
  script_bugtraq_id(46822, 46849);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari Multiple Vulnerabilities - April 2011 (Mac OS X)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4596");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2011/Apr/msg00002.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_require_keys("AppleSafari/MacOSX/Version");
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

safVer = get_kb_item("AppleSafari/MacOSX/Version");
if(!safVer){
  exit(0);
}

## Grep for Apple Safari Versions prior to 5.0.5
if(version_is_less(version:safVer, test_version:"5.0.5")){
  security_message(0);
}
