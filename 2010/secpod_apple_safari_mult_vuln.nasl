###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_safari_mult_vuln.nasl 8485 2018-01-22 07:57:57Z teissa $
#
# Apple Safari multiple vulnerabilities (Mar10)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-18-2010
#  Added the CVE and related description.
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to send a
malformed CSS stylesheet tag containing an overly long string, which leads to
application crash or possibly execute arbitrary code on the system.

Impact Level: System/Application";

tag_affected = "Apple Saferi version 4.0.5 and lower";

tag_insight = 
"The flaws are cuased by,
 - Error in the 'CSSSelector()' function when handling CSS stylesheet tag
   containing an overly long string.
 - Improper bounds checking by the 'WebKit' library when processing CSS
   stylesheet tag containing an overly long string.
 - Use-after-free error when handling of a deleted window object, allows attackers
   to execute arbitrary code by using 'window.open' to create a popup window for
   a crafted HTML document, and then calling the parent window&qts close method.
 - Includes HTTP basic authentication credentials in an HTTP request if a web page
   that requires HTTP basic authentication redirects to a different domain.";

tag_solution = "Upgrade to Apple Saferi 5.0 or later,
For updates refer to http://support.apple.com/downloads";

tag_summary = "The host is running Apple Saferi and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902025");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2010-1029", "CVE-2010-1939", "CVE-2010-1939");
  script_bugtraq_id(38398, 39990);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Apple Saferi multiple vulnerabilities (Mar10)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39670");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56524");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56527");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11567");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1097");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/May/1023958.html");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_GATHER_INFO);
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

## Get Apple Safari version from KB
safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer){
  exit(0);
}

## Check for Apple Safari Version 4.0.5(5.31.22.7).
## Included version 4.0.5 because exploit is working
if(version_is_less_equal(version:safariVer, test_version:"5.31.22.7")){
  security_message(0);
}
