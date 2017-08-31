# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0102.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131253");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-03-08 07:15:16 +0200 (Tue, 08 Mar 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0102");
script_tag(name: "insight", value: "The BER decoder would crash due to reading from offset 0 of an empty vector if it encountered a BIT STRING which did not contain any data at all. This can be used to easily crash applicatons reading untrusted ASN.1 data, but does not seem exploitable for code execution (CVE-2015-5726). The BER decoder would allocate a fairly arbitrary amount of memory in a length field, even if there was no chance the read request would succeed. This might cause the process to run out of memory or invoke the OOM killer (CVE-2015-5727). The ressol function implements the Tonelli-Shanks algorithm for finding square roots could be sent into a nearly infinite loop due to a misplaced conditional check. This could occur if a composite modulus is provided, as this algorithm is only defined for primes. This function is exposed to attacker controlled input via the OS2ECP function during ECC point decompression (CVE-2016-2194). The PointGFp constructor did not check that the affine coordinate arguments were less than the prime, but then in curve multiplication assumed that both arguments if multiplied would fit into an integer twice the size of the prime. The bigint_mul and bigint_sqr functions received the size of the output buffer, but only used it to dispatch to a faster algorithm in cases where there was sufficient output space to call an unrolled multiplication function. The result is a heap overflow accessible via ECC point decoding, which accepted untrusted inputs. This is likely exploitable for remote code execution. On systems which use the mlock pool allocator, it would allow an attacker to overwrite memory held in secure_vector objects. After this point the write will hit the guard page at the end of the mmap'ed region so it probably could not be used for code execution directly, but would allow overwriting adjacent key material (CVE-2016-2195)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0102.html");
script_cve_id("CVE-2015-5726","CVE-2015-5727","CVE-2016-2194","CVE-2016-2195");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0102");
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
if ((res = isrpmvuln(pkg:"botan", rpm:"botan~1.10.12~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"monotone", rpm:"monotone~1.1~4.1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"softhsm", rpm:"softhsm~1.3.4~5.1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
