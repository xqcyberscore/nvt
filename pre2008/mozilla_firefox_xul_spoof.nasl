# OpenVAS Vulnerability Test
# $Id: mozilla_firefox_xul_spoof.nasl 7573 2017-10-26 09:18:50Z cfischer $
# Description: Mozilla/Firefox user interface spoofing
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Updated: 03/12/2009 Antu Sanadi <santu@secpod.com> 
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host is using Mozilla and/or Firefox, an alternative web browser.
  This web browser supports the XUL (XML User Interface Language), a language
  designed to manipulate the user interface of the browser itself.

  Since XUL gives the full control of the browser GUI to the visited websites,
  an attacker may use it to spoof a third party website and therefore pretend
  that the URL and Certificates of the website are legitimate.

  In addition to this, the remote version of this browser is vulnerable to a
  flaw which may allow a malicious web site to spoof security properties
  such as SSL certificates and URIs.";

tag_solution = "None at this time";

if(description)
{
  script_id(14181);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10796, 10832);
  script_cve_id("CVE-2004-0763", "CVE-2004-0764");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla/Firefox user interface spoofing");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.nd.edu/~jsmith30/xul/test/spoof.html");
  exit(0);

}

include("version_func.inc");

mozVer = get_kb_item("Firefox/Win/Ver");
if(mozVer)
{
  # check firefox version < 1.7
  if(version_is_less(version:mozVer ,test_version:"1.7"))
  {
    security_message(0);
    exit(0);
  }
}

tunBirdVer = get_kb_item("Thunderbird/Win/Ver");
if(!tunBirdVer){
  exit(0);
}

# check for thunderbird version < 0.7
if(version_is_less(version:tunBirdVer ,test_version:"0.7")){
  security_message(0);
}
