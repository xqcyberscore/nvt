# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0079.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
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
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.131241");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-02-22 07:35:31 +0200 (Mon, 22 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0079");
script_tag(name: "insight", value: "Updated glibc fixes the following security issues: A stack overflow (unbounded alloca) could have caused applications which process long strings with the nan function to crash or, potentially, execute arbitrary code (CVE-2014-9761). A stack-based buffer overflow in getaddrinfo allowed remote attackers to cause a crash or execute arbitrary code via crafted and timed DNS responses (CVE-2015-7547). Out-of-range time values passed to the strftime function may cause it to crash, leading to a denial of service, or potentially disclosure information (CVE-2015-8776). Insufficient checking of LD_POINTER_GUARD environment variable allowed local attackers to bypass the pointer guarding protection of the dynamic loader on set-user-ID and set-group-ID programs (CVE-2015-8777). Integer overflow in hcreate and hcreate_r could have caused an out-of-bound memory access. leading to application crashes or, potentially, arbitrary code execution (CVE-2015-8778). A stack overflow (unbounded alloca) in the catopen function could have caused applications which pass long strings to the catopen function to crash or, potentially execute arbitrary code (CVE-2015-8779)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0079.html");
script_cve_id("CVE-2014-9761","CVE-2015-7547","CVE-2015-8776","CVE-2015-8777","CVE-2015-8778","CVE-2015-8779");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0079");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.20~21.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
