###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mem_corr_vuln_jul12_win.nasl 10135 2018-06-08 11:42:28Z asteins $
#
# Mozilla Products Memory Corruption Vulnerabilities - July12 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802895");
  script_version("$Revision: 10135 $");
  script_cve_id("CVE-2012-1949", "CVE-2012-1960");
  script_bugtraq_id(54580, 54572);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 13:42:28 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2012-07-24 11:13:01 +0530 (Tue, 24 Jul 2012)");
  script_name("Mozilla Products Memory Corruption Vulnerabilities - July12 (Windows)");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/49965");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027256");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027257");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-42.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-50.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name : "impact" , value : "Successful exploitation could allow attackers to obtain sensitive
  information, execute arbitrary code in the context of the browser or cause a
  denial of service.
  Impact Level: System/Application");
  script_tag(name : "affected" , value : "SeaMonkey version before 2.11
  Thunderbird version 5.0 through 13.0
  Mozilla Firefox version 4.x through 13.0 on Windows");
  script_tag(name : "insight" , value : "- An out-of-bounds read error in the qcms_transform_data_rgb_out_lut_sse2
    function in the QCMS implementation, can be exploited to disclose certain
    process memory via a crafted color profile.
  - Multiple unspecified errors within the browser engine can be exploited to
    corrupt memory.");
  script_tag(name : "summary" , value : "This host is installed with Mozilla firefox/thunderbird/seamonkey and is
  prone to multiple vulnerabilities.");
  script_tag(name : "solution" , value : "Upgrade to Mozilla Firefox version 14.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.11 or later,
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 14.0 or later,
  http://www.mozilla.org/en-US/thunderbird/");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");


ffVer = "";
ffVer = get_kb_item("Firefox/Win/Ver");

if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"9.0.1")||
     version_in_range(version:ffVer, test_version:"11.0", test_version2:"13.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# SeaMonkey Check
seaVer = "";
seaVer = get_kb_item("Seamonkey/Win/Ver");

if(seaVer)
{
  if(version_is_less(version:seaVer, test_version:"2.11"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# Thunderbird Check
tbVer = "";
tbVer = get_kb_item("Thunderbird/Win/Ver");

if(tbVer)
{
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"9.0.1")||
     version_in_range(version:tbVer, test_version:"11.0", test_version2:"13.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
