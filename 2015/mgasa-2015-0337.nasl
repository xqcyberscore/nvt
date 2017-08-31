# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0337.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.130049");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:42:02 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0337");
script_tag(name: "insight", value: "Updated openafs packages fix security vulnerabilities: Memory allocated by vos for VLDB entry structures was not cleared prior to use, meaning stack data could be sent over the network, possibly in the clear if crypt mode was not in use (CVE-2015-3282). The default use by bos of clear rather than crypt mode can allow spoofing commands, including some which modify server state if restricted mode was not enabled (CVE-2015-3283). A local user executing commands which make pioctl calls to the kernel will have some contents of kernel memory leaked when buffers used are larger than data being returned (CVE-2015-3284). A local user executing the OSD FS command pioctl can trigger a panic due to an incorrect buffer being used for return status of the command (CVE-2015-3285). The vlserver allows pattern matching on volume names via regular expressions when listing attributes. Because the regular expression is not checked for situations which can overflow the buffers used, an attack is possible which reads arbitrary memory beyond the end of the buffer and can act on it as part of the expression evaluation, potentially crashing the process (CVE-2015-6587)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0337.html");
script_cve_id("CVE-2015-3282","CVE-2015-3283","CVE-2015-3284","CVE-2015-3285","CVE-2015-6587");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0337");
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
if ((res = isrpmvuln(pkg:"openafs", rpm:"openafs~1.6.13~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
