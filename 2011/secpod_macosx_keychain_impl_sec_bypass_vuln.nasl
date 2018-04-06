###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_keychain_impl_sec_bypass_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apple Mac OS X Keychain Certificate Settings Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to bypass security
restrictions and launch further attacks on the system.

Impact Level: System";

tag_affected = "Mac OS X version 10.6 to 10.6.8 and
Mac OS X Server version 10.6 to 10.6.8";

tag_insight = "The flaw is due to an error in the implementation of Certificate
Trust Policy, which allows attacker to bypass KeyChain security settings to accept
an Extended Validation certificate as valid.";

tag_solution = "Upgrade to Mac OS X version 10.7.3 or later.
For updates refer to http://support.apple.com/downloads/";

tag_summary = "This host is installed with Mac OS X and is prone to the security
bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902474");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_cve_id("CVE-2011-3422");
  script_bugtraq_id(49429);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Apple Mac OS X Keychain Certificate Settings Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69556");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1026002");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login/osx_name","ssh/login/osx_version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-macosx.inc");
include("version_func.inc");

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
 exit(0);
}

## Check for the Mac OS X
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS versions
  if(version_in_range(version:osVer, test_version:"10.6.0", test_version2:"10.6.8")){
    security_message(0);
  }
}
