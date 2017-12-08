# OpenVAS Vulnerability Test
# $Id: mozilla_CB-A08-0017.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Mozilla Firefox, Thunderbird, Seamonkey. Several vulnerabilitys (Linux)
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
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

tag_summary = "The remote host is probable affected by the vulnerabilitys described in 
CVE-2008-0416, CVE-2007-4879, CVE-2008-1195, CVE-2008-1233,
CVE-2008-1234, CVE-2008-1235, CVE-2008-1236, CVE-2008-1237,
CVE-2008-1238, CVE-2008-1240, CVE-2008-1241 and more.


Impact
     Mozilla contributors moz_bug_r_a4, Boris Zbarsky, 
     and Johnny Stenback reported a series of vulnerabilities 
     which allow scripts from page content to run with elevated
     privileges. moz_bug_r_a4 demonstrated additional variants
     of MFSA 2007-25 and MFSA2007-35 (arbitrary code execution
     through XPCNativeWrapper pollution). Additional 
     vulnerabilities reported separately by Boris Zbarsky, 
     Johnny Stenback, and moz_bug_r_a4 showed that the browser
     could be forced to run JavaScript code using the wrong 
     principal leading to universal XSS and arbitrary code execution.
     And more...";

tag_solution = "All Users should upgrade to the latest versions of Firefox, Thunderbird or Seamonkey.";

# $Revision: 8023 $

if(description)
{

 script_id(90014);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-06-17 20:22:38 +0200 (Tue, 17 Jun 2008)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241", "CVE-2008-0412", "CVE-2008-0416");
 name = "Mozilla Firefox, Thunderbird, Seamonkey. Several vulnerabilitys (Linux)";
 script_name(name);

 script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-14.html");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
 family = "General";
 script_family(family);
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);

 # This NVT is broken in many ways...
 script_tag(name:"deprecated", value:TRUE); 

 exit(0);
}

exit(66);

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

r = find_bin(prog_name:"firefox", sock:sock);
foreach binary_name (r) {
  binary_name = chomp(binary_name);
  ver = get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"([0-9\.]+)");
  if(ver != NULL) {
    if(version_is_less(version:ver[0], test_version:"2.0.0.14") ) {
      security_message(port:0);
      report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
      security_message(port:0, data:report);
    } 
  }
}
r = find_bin(prog_name:"thunderbird", sock:sock);
foreach binary_name (r) {
  binary_name = chomp(binary_name);
  ver = get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"([0-9\.]+)");
  if(ver != NULL) {
    if(version_is_less(version:ver[0], test_version:"2.0.0.14") ) {
      security_message(port:0);
      report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
      security_message(port:0, data:report);
    } 
  }
}
r = find_bin(prog_name:"seamonkey", sock:sock);
foreach binary_name (r) {
  binary_name = chomp(binary_name);
  ver = get_bin_version(full_prog_name:binary_name, version_argv:"--version", ver_pattern:"([0-9\.]+)");
  if(ver != NULL) {
    if(version_is_less(version:ver[0], test_version:"1.1.9") ) {
      security_message(port:0);
      report = string("\nFound : ") + binary_name + "  Version : " + ver[max_index(ver)-1] + string("\n");
      security_message(port:0, data:report);
    } 
  }
}

exit(0);
