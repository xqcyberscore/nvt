###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thunderbird_mult_vuln_mar09_lin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Mozilla Thunderbird Multiple Vulnerabilities Mar-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will let attacker execute arbitrary code in the
  context of an affected web application or can cause URL address bar
  spoofing attacks or may cause denial of service.
  Impact Level: System/Application";
tag_affected = "Thunderbird version prior to 2.0.0.21 on Linux.";
tag_insight = "Multiple flaws due to,
  - Layout engine error which causes memory corruption and assertion failures.
  - Layout engine error related to 'nsCSSStyleSheet::GetOwnerNode', events and
    garage collection which triggers memory corruption.
  - Layout engine error through a splice of an array that contains 'non-set'
    elements which causes 'jsarray.cpp' to pass an incorrect argument to the
    'ResizeSlots' function which causes application crash.
  - Vectors related to js_DecompileValueGenerator, jsopcode.cpp,
    __defineSetter__ and watch which causes a segmentation fault.
  -  Layout engine error in the vector related to 'gczeal'.
  - Double free vulnerability in Thunderbird via 'cloned XUL DOM elements'
    which were linked as a parent and child are not properly handled during
    garbage collection which causes arbitrary code execution.
  - 'nsIRDFService' in Thunderbird allows to bypass the same origin policy and
    read XML data through another domain by cross-domain redirect.
  - Error while decoding invisible characters when they are displayed in the
    location bar which causes incorrect address to be displayed in the URL bar
    and causes spoofing attacks.";
tag_solution = "Upgrade to Thunderbird version 2.0.0.21
  http://www.mozilla.com/en-US/thunderbird";
tag_summary = "The host is installed with Mozilla Thunderbird and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800364");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-10 11:59:23 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774",
                "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777");
  script_bugtraq_id(33990);
  script_name("Mozilla Thunderbird Multiple Vulnerabilities Mar-09 (Linux)");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-07.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-08.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-09.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-11.html");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/33969.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_thunderbird_detect_lin.nasl");
  script_require_keys("Thunderbird/Linux/Ver");
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

tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(!tbVer){
  exit(0);
}

# Grep for Thunderbird version < 2.0.0.21
if(version_is_less(version:tbVer, test_version:"2.0.0.21")){
  security_message(0);
}
