# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0093.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.131244");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-03-03 14:39:15 +0200 (Thu, 03 Mar 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0093");
script_tag(name: "insight", value: "Update openssl packages fix security vulnerabilities: Yuval Yarom from the University of Adelaide and NICTA, Daniel Genkin from Technion and Tel Aviv University, and Nadia Heninger from the University of Pennsylvania discovered a side-channel attack which makes use of cache-bank conflicts on the Intel Sandy-Bridge microarchitecture. This could allow local attackers to recover RSA private keys (CVE-2016-0702). Adam Langley from Google discovered a double free bug when parsing malformed DSA private keys. This could allow remote attackers to cause a denial of service or memory corruption in applications parsing DSA private keys received from untrusted sources (CVE-2016-0705). Guido Vranken discovered an integer overflow in the BN_hex2bn and BN_dec2bn functions that can lead to a NULL pointer dereference and heap corruption. This could allow remote attackers to cause a denial of service or memory corruption in applications processing hex or dec data received from untrusted sources (CVE-2016-0797). Emilia Ksper of the OpenSSL development team discovered a memory leak in the SRP database lookup code. To mitigate the memory leak, the seed handling in SRP_VBASE_get_by_user is now disabled even if the user has configured a seed. Applications are advised to migrate to the SRP_VBASE_get1_by_user function (CVE-2016-0798). Guido Vranken discovered an integer overflow in the BIO_*printf functions that could lead to an OOB read when printing very long strings. Additionally the internal doapr_outch function can attempt to write to an arbitrary memory location in the event of a memory allocation failure. These issues will only occur on platforms where sizeof(size_t) > sizeof(int) like many 64 bit systems. This could allow remote attackers to cause a denial of service or memory corruption in applications that pass large amounts of untrusted data to the BIO_*printf functions (CVE-2016-0799). Note that Mageia is not vulnerable to the DROWN issue, also known as CVE-2016-0800, in its default configuration, as SSLv2 was disabled by default in Mageia 5. However, upstream mitigations for DROWN have also been incorporated into this update, protecting systems that may have enabled it."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0093.html");
script_cve_id("CVE-2016-0702","CVE-2016-0705","CVE-2016-0797","CVE-2016-0798","CVE-2016-0799");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0093");
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
if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.2g~1.1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
