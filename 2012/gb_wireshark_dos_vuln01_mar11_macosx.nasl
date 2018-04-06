###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln01_mar11_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Wireshark Denial of Service Vulnerability-01 March 11 (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to cause a
denial of service via vectors involving self-referential ASN.1 CHOICE values.

Impact Level: System/Application";

tag_affected = "Wireshark version 1.2.0 through 1.2.15
Wireshark version 1.4.0 through 1.4.4";

tag_insight = "The flaw is due to stack consumption vulnerability in the
'dissect_ber_choice function' in the 'BER dissector'.";

tag_solution = "Upgrade to version 1.4.4-1 or later,
For updates refer to http://www.wireshark.org/download.html";

tag_summary = "The host is installed with Wireshark and is prone to denial of
service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802799");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-1142");
  script_bugtraq_id(46626);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-27 15:59:15 +0530 (Wed, 27 Jun 2012)");
  script_name("Wireshark Denial of Service Vulnerability-01 March 11 (Mac OS X)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65912");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=1516");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
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

## Variable Initialization
wiresharkVer = "";

## Get the version from KB
wiresharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!wiresharkVer){
  exit(0);
}

## Check for Wireshark Version
if(version_in_range(version:wiresharkVer, test_version:"1.2.0", test_version2:"1.2.15")||
   version_in_range(version:wiresharkVer, test_version:"1.4.0", test_version2:"1.4.4")){
   security_message(0);
}
