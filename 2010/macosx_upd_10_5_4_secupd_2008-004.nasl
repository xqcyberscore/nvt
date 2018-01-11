###################################################################
# OpenVAS Vulnerability Test
#
# Mac OS X 10.5.4 Update / Mac OS X Security Update 2008-004
#
# LSS-NVT-2010-021
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

tag_solution = "Update your Mac OS X operating system.

 For more information see:
 http://support.apple.com/kb/HT2163";

tag_summary = "The remote host is missing Mac OS X 10.5.4 Update / Mac OS X Security Update 2008-004.
 One or more of the following components are affected:

 Alias Manager
 CoreTypes
 c++filt
 Dock
 Launch Services
 Net-SNMP
 Ruby
 SMB File Server
 System Configuration
 Tomcat
 VPN
 WebKit";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.102032");
 script_version("$Revision: 8338 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
 script_cve_id("CVE-2008-2308","CVE-2008-2309","CVE-2008-2310","CVE-2008-2314","CVE-2008-2311","CVE-2008-0960","CVE-2008-2662","CVE-2008-2663","CVE-2008-2664","CVE-2008-2725","CVE-2008-2726","CVE-2008-1145","CVE-2008-1105","CVE-2008-2313","CVE-2005-3164","CVE-2007-1355","CVE-2007-2449","CVE-2007-2450","CVE-2007-3382","CVE-2007-3383","CVE-2007-5333","CVE-2007-3385","CVE-2007-5461","CVE-2007-6276","CVE-2008-2307");
 script_name("Mac OS X 10.5.4 Update / Mac OS X Security Update 2008-004");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (C) 2010 LSS");
 script_family("Mac OS X Local Security Checks");
 script_require_ports("Services/ssh", 22);
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/osx_name","ssh/login/osx_version");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

include("pkg-lib-macosx.inc");
include("version_func.inc");

ssh_osx_name = get_kb_item("ssh/login/osx_name");
if (!ssh_osx_name) exit (0);

ssh_osx_ver = get_kb_item("ssh/login/osx_version");
if (!ssh_osx_ver) exit (0);

ssh_osx_rls = ssh_osx_name + ' ' + ssh_osx_ver;

pkg_for_ver = make_list("Mac OS X 10.4.11","Mac OS X Server 10.4.11","Mac OS X 10.5.3","Mac OS X Server 10.5.3");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_message(0); exit(0);}

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.4.11")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.4.11"))) { security_message(0); exit(0);}
    else if ((ssh_osx_ver==osx_ver(ver:"Mac OS X 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.004"))) { security_message(0); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.4.11")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.4.11"))) { security_message(0); exit(0);}
    else if ((ssh_osx_ver==osx_ver(ver:"Mac OS X Server 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2008.004"))) { security_message(0); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.3")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.5.4")) { security_message(0); exit(0); }
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.3")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.5.4")) { security_message(0); exit(0); }
}
