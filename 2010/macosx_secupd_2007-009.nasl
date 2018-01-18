###################################################################
# OpenVAS Vulnerability Test
#
# Mac OS X Security Update 2007-009
#
# LSS-NVT-2010-012
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
 http://support.apple.com/kb/HT2012";

tag_summary = "The remote host is missing Security Update 2007-009.
 One or more of the following components are affected:

 Address Book
 CFNetwork
 ColorSync
 Core Foundation
 CUPS
 Desktop Services
 Flash Player Plug-in
 GNU Tar
 iChat
 IO Storage Family
 Launch Services
 Mail
 perl
 python
 Quick Look
 ruby
 Safari
 Safari RSS
 Samba
 Shockwave Plug-in
 SMB
 Software Update
 Spin Tracer
 Spotlight
 tcpdump
 XQuery";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.102023");
 script_version("$Revision: 8440 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
 script_cve_id("CVE-2007-4708","CVE-2007-4709","CVE-2007-4710","CVE-2007-5847","CVE-2007-5848","CVE-2007-4351","CVE-2007-5849","CVE-2007-5850","CVE-2007-5476","CVE-2007-4131","CVE-2007-5851","CVE-2007-5853","CVE-2007-5854","CVE-2007-6165","CVE-2007-5855","CVE-2007-5116","CVE-2007-4965","CVE-2007-5856","CVE-2007-5857","CVE-2007-5770","CVE-2007-5379","CVE-2007-5380","CVE-2007-6077","CVE-2007-5858","CVE-2007-5859","CVE-2007-4572","CVE-2007-5398","CVE-2006-0024","CVE-2007-3876","CVE-2007-5863","CVE-2007-5860","CVE-2007-5861","CVE-2007-1218","CVE-2007-3798","CVE-2007-1659","CVE-2007-1660","CVE-2007-1661","CVE-2007-1662","CVE-2007-4766","CVE-2007-4767","CVE-2007-4768");
 script_name("Mac OS X Security Update 2007-009");
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

pkg_for_ver = make_list("Mac OS X 10.4.11","Mac OS X Server 10.4.11","Mac OS X 10.5.1","Mac OS X Server 10.5.1");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_message(0); exit(0);}

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.4.11")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.4.11"))) { security_message(0); exit(0);}
    else if ((ssh_osx_ver==osx_ver(ver:"Mac OS X 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2007.009"))) { security_message(0); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.4.11")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.4.11"))) { security_message(0); exit(0);}
    else if ((ssh_osx_ver==osx_ver(ver:"Mac OS X Server 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2007.009"))) { security_message(0); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.1")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.5.1"))) { security_message(0); exit(0);}
    else if ((ssh_osx_ver==osx_ver(ver:"Mac OS X 10.5.1")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2007.009"))) { security_message(0); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.1")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.5.1"))) { security_message(0); exit(0);}
    else if ((ssh_osx_ver==osx_ver(ver:"Mac OS X Server 10.5.1")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2007.009"))) { security_message(0); exit(0);}
}
