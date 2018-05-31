###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_su11-002.nasl 10023 2018-05-30 09:57:40Z cfischer $
#
# Mac OS X v10.6.7 Multiple Vulnerabilities (2011-002)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902468");
  script_version("$Revision: 10023 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 11:57:40 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2011-08-25 09:25:35 +0200 (Thu, 25 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mac OS X v10.6.7 Multiple Vulnerabilities (2011-002)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT1222");
  script_xref(name : "URL" , value : "https://ssl.apple.com/support/security/pgp/");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce//2011//Apr/msg00003.html");

  script_copyright("Copyright (c) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");

  script_tag(name : "impact" , value : "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions or cause a denial-of-service condition.

  Impact Level: System/Application");
  script_tag(name : "affected" , value : "Certificate Trust Policy.");
  script_tag(name : "insight" , value : "For more information on the vulnerabilities refer to the links below.");
  script_tag(name : "solution" , value : "Run Mac Updates and update the Security Update 2011-002

  For updates refer to http://support.apple.com/kb/HT1222");
  script_tag(name : "summary" , value : "This host is missing an important security update according to
  Mac OS X 10.6.7 Update/Mac OS X Security Update 2011-002.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-macosx.inc");
include("version_func.inc");

osName = get_kb_item( "ssh/login/osx_name" );
if( ! osName ) exit( 0 );

osVer = get_kb_item( "ssh/login/osx_version" );
if( ! osVer ) exit( 0 );

if( "Mac OS X" >< osName || "Mac OS X Server" >< osName ) {
  if( version_is_less_equal( version:osVer, test_version:"10.5.8" ) ||
      version_in_range( version:osVer, test_version:"10.6", test_version2:"10.6.7" ) ) {
    if( isosxpkgvuln( fixed:"com.apple.pkg.update.security.", diff:"2011.002" ) ) {
      report = report_fixed_ver( installed_version:osName + " " + osVer, fixed_version:"Install the missing security update 2011.002" );
      security_message( port:0, data:report );
      exit( 0 );
    }
  }
}
