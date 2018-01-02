###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_libxml_dos_vuln.nasl 8246 2017-12-26 07:29:20Z teissa $
#
# Apple Safari libxml Denial of Service Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to cause a denial
of service.

Impact Level: Application";

tag_affected = "Apple Safari version 5.0.2 and prior.";

tag_insight = "The flaw is due to an error when traversing the XPath axis of
certain XML files. This can be exploited to cause a crash when an application
using the library processes a specially crafted XML file.";

tag_solution = "Upgrade to Apple Safari 5.0.4 or later, 
For updates refer to http://www.apple.com/support/downloads";


tag_summary = "The host is installed with Apple Safari web browser and is prone
  to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801638");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_cve_id("CVE-2010-4008");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Apple Safari libxml Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42175/");
  script_xref(name : "URL" , value : "http://blog.bkis.com/en/libxml2-vulnerability-in-google-chrome-and-apple-safari/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

## Grep for Apple Safari Versions prior to 5.0.2 (5.33.18.5)
if(version_is_less_equal(version:safVer, test_version:"5.33.18.5")){
  security_message(0);
}
