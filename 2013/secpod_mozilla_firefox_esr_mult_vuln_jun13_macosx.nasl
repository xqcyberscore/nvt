###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_firefox_esr_mult_vuln_jun13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Mozilla Firefox ESR Multiple Vulnerabilities - June 13 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code,
  obtain potentially sensitive information, gain escalated privileges, bypass
  security restrictions, and perform unauthorized actions. Other attacks may
  also be possible.
  Impact Level: Application";

tag_affected = "Mozilla Firefox ESR version 17.x before 17.0.7 on Mac OS X";
tag_insight = "Multiple flaws due to,
  - PreserveWrapper does not handle lack of wrapper.
  - Error in processing of SVG format images with filters to read pixel values.
  - Does not prevent inclusion of body data in XMLHttpRequest HEAD request.
  - Multiple unspecified vulnerabilities in the browser engine.
  - Does not properly handle onreadystatechange events in conjunction with
    page reloading.
  - System Only Wrapper (SOW) and Chrome Object Wrapper (COW), does not
    restrict XBL user-defined functions.
  - Use-after-free vulnerability in 'nsIDocument::GetRootElement' and
    'mozilla::dom::HTMLMediaElement::LookupMediaElementURITable' functions.
  - XrayWrapper does not properly restrict use of DefaultValue for method calls.";
tag_solution = "Upgrade to Mozilla Firefox ESR version 17.0.7 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "This host is installed with Mozilla Firefox ESR and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903219");
  script_version("$Revision: 9353 $");
  script_cve_id( "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687",
                 "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694",
                 "CVE-2013-1697", "CVE-2013-1682");
  script_bugtraq_id(60766, 60773, 60774, 60777, 60778, 60783, 60787, 60776, 60784,
                    60765);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-06-26 17:27:11 +0530 (Wed, 26 Jun 2013)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities - June 13 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53970");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028702");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2013/mfsa2013-50.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
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

# Firefox Check
ffVer = "";
ffVer = get_kb_item("Mozilla/Firefox-ESR/MacOSX/Version");

if(ffVer && ffVer =~ "^17.0")
{
  # Grep for Firefox version
  if(version_in_range(version:ffVer, test_version:"17.0", test_version2:"17.0.6"))
  {
    security_message(0);
    exit(0);
  }
}
