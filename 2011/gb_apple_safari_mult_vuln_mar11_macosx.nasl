###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_mar11_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apple Safari Multiple Vulnerabilities - March 2011 (Mac OS X)
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

tag_impact = "Successful exploitation will allow attacker to disclose potentially
  sensitive information, conduct cross-site scripting and spoofing attacks,
  and compromise a user's system.
  Impact Level: System/Application";
tag_affected = "Apple Safari versions prior to 5.0.4";
tag_insight = "For more details about the vulnerabilities refer the reference section.";
tag_solution = "Upgrade to Apple Safari version 5.0.4 or later,
  For updates refer to http://www.apple.com/safari/download/";
tag_summary = "The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802235");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_cve_id("CVE-2010-1824", "CVE-2010-4008", "CVE-2010-4494", "CVE-2011-0111",
                "CVE-2011-0112", "CVE-2011-0113", "CVE-2011-0114", "CVE-2011-0115",
                "CVE-2011-0116", "CVE-2011-0117", "CVE-2011-0118", "CVE-2011-0119",
                "CVE-2011-0120", "CVE-2011-0121", "CVE-2011-0122", "CVE-2011-0123",
                "CVE-2011-0124", "CVE-2011-0125", "CVE-2011-0126", "CVE-2011-0127",
                "CVE-2011-0128", "CVE-2011-0129", "CVE-2011-0130", "CVE-2011-0131",
                "CVE-2011-0132", "CVE-2011-0133", "CVE-2011-0134", "CVE-2011-0135",
                "CVE-2011-0136", "CVE-2011-0137", "CVE-2011-0138", "CVE-2011-0139",
                "CVE-2011-0140", "CVE-2011-0141", "CVE-2011-0142", "CVE-2011-0143",
                "CVE-2011-0144", "CVE-2011-0145", "CVE-2011-0146", "CVE-2011-0147",
                "CVE-2011-0148", "CVE-2011-0149", "CVE-2011-0150", "CVE-2011-0151",
                "CVE-2011-0152", "CVE-2011-0153", "CVE-2011-0154", "CVE-2011-0155",
                "CVE-2011-0156", "CVE-2011-0160", "CVE-2011-0161", "CVE-2011-0163",
                "CVE-2011-0165", "CVE-2011-0166", "CVE-2011-0167", "CVE-2011-0168",
                "CVE-2011-0169");
  script_bugtraq_id(44779, 46677, 46684, 46686, 46687, 46688, 46689, 46690, 46691,
                    46692, 46693, 46694, 46695, 46696, 46698, 46699, 46700, 46701,
                    46702, 46704, 46705, 46706, 46707, 46708, 46709, 46710, 46711,
                    46712, 46713, 46714, 46715, 46716, 46717, 46718, 46719, 46720,
                    46721, 46722, 46723, 46724, 46725, 46726, 46727, 46728, 46744,
                    46745, 46746, 46747, 46748, 46749, 46808, 46809, 46811, 46814,
                    46816);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari Multiple Vulnerabilities - March 2011 (Mac OS X)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4566");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43696");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2011/mar/msg00004.html");

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

## Grep for Apple Safari Versions prior to 5.0.4
if(version_is_less(version:safVer, test_version:"5.0.4")){
  security_message(0);
}
