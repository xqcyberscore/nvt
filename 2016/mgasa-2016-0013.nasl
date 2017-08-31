# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0013.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131176");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-01-14 07:28:49 +0200 (Thu, 14 Jan 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0013");
script_tag(name: "insight", value: "It was found that float-parsing code used in Mono before 4.2 is derived from code vulnerable to CVE-2009-0689. The issue concerns the 'freelist' array, which is a global array of 16 pointers to 'Bigint'. This array is part of a memory allocation and reuse system which attempts to reduce the number of 'malloc' and 'free' calls. The system allocates blocks in power-of-two sizes, from 2^0 through 2^15, and stores freed blocks of each size in a linked list rooted at the corresponding cell of 'freelist'. The 'Balloc' and 'Bfree' functions which operate this system fail to check if the size parameter 'k' is within the allocated 0..15 range. As a result, a sufficiently large allocation will have k=16 and treat the word immediately after 'freelist' as a pointer to a previously-allocated chunk. The specific results may vary significantly based on the version, platform, and compiler, since they depend on the layout of variables in memory. An attacker who can cause a carefully-chosen string to be converted to a floating-point number can cause a crash and potentially induce arbitrary code execution."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0013.html");
script_cve_id("CVE-2009-0689");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0013");
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
if ((res = isrpmvuln(pkg:"mono", rpm:"mono~3.12.1~1.2.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
