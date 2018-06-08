# OpenVAS Vulnerability Test
# $Id: smbcl_mozilla.nasl 10135 2018-06-08 11:42:28Z asteins $
# Description: Mozilla Firefox, Thunderbird, Seamonkey. Several vulnerabilitys (Windows)
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
# Modified to implement through 'smb_nt.inc'
#  - By Sharath S <sharaths@secpod.com> On 2009-09-17
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# $Revision: 10135 $

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90013");
  script_version("$Revision: 10135 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 13:42:28 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2008-06-17 20:22:38 +0200 (Tue, 17 Jun 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0412", "CVE-2008-0416", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241");
  script_bugtraq_id(28448);
  script_name("Mozilla Firefox, Thunderbird, Seamonkey. Several vulnerabilitys (Windows)");
 script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-14.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name : "solution" , value : "All Users should upgrade to the latest versions of Firefox, Thunderbird or
  Seamonkey.
  http://www.mozilla.com/en-US/firefox/all.html
  http://www.seamonkey-project.org/releases/
  http://www.mozillamessaging.com/en-US/thunderbird/all.html");
  script_tag(name : "summary" , value : "The remote host is probable affected by the vulnerabilities described in
  CVE-2008-0416, CVE-2007-4879, CVE-2008-1195, CVE-2008-1233,
  CVE-2008-1234, CVE-2008-1235, CVE-2008-1236, CVE-2008-1237,
  CVE-2008-1238, CVE-2008-1240, CVE-2008-1241 and more.");
  script_tag(name : "impact" , value : "Mozilla contributors moz_bug_r_a4, Boris Zbarsky, and Johnny Stenback reported
  a series of vulnerabilities which allow scripts from page content to run with
  elevated privileges. moz_bug_r_a4 demonstrated additional variants of MFSA
  2007-25 and MFSA2007-35 (arbitrary code execution through XPCNativeWrapper
  pollution). Additional vulnerabilities reported separately by Boris Zbarsky,
  Johnny Stenback, and moz_bug_r_a4 showed that the browser could be forced to
  run JavaScript code using the wrong principal leading to universal XSS
  and arbitrary code execution.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");


ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_less(version:ffVer, test_version:"2.0.0.14"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer)
{
  if(version_is_less(version:smVer, test_version:"1.1.9"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_is_less(version:tbVer, test_version:"2.0.0.14")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
