###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_thunderbird_esr_mult_vuln_jun13_win.nasl 2933 2016-03-24 08:20:46Z benallard $
#
# Mozilla Thunderbird ESR Multiple Vulnerabilities - June 13 (Windows)
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

tag_affected = "Thunderbird ESR versions 17.x before 17.0.7 on Windows";
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
tag_solution = "Upgrade to Thunderbird ESR 17.0.7 or later
  For updates refer to http://www.mozilla.org/en-US/thunderbird";
tag_summary = "The host is installed with Mozilla Thunderbird ESR and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(903217);
  script_version("$Revision: 2933 $");
  script_cve_id( "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687",
                 "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694",
                 "CVE-2013-1697", "CVE-2013-1682");
  script_bugtraq_id(60765, 60766, 60773, 60774, 60777, 60778, 60783, 60787, 60776,
                    60784);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:20:46 +0100 (Thu, 24 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-06-26 17:09:51 +0530 (Wed, 26 Jun 2013)");
  script_name("Mozilla Thunderbird ESR Multiple Vulnerabilities - June 13 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53970");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028702");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2013/mfsa2013-50.html");
  script_summary("Check for the vulnerable version of Mozilla Thunderbird ESR on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird-ESR/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

# Variable Initialization
tbVer = "";

# Thunderbird Check
tbVer = get_kb_item("Thunderbird-ESR/Win/Ver");
if(tbVer && tbVer =~ "^17.0")
{
  # Grep for Thunderbird version
  if(version_in_range(version:tbVer, test_version:"17.0", test_version2:"17.0.6")){
    security_message(0);
    exit(0);
  }
}
