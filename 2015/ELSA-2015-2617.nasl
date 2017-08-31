# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2617.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.122803");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-12-15 02:50:30 +0200 (Tue, 15 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2617");
script_tag(name: "insight", value: "ELSA-2015-2617 -  openssl security update - [1.0.1e-51.1]- fix CVE-2015-3194 - certificate verify crash with missing PSS parameter- fix CVE-2015-3195 - X509_ATTRIBUTE memory leak- fix CVE-2015-3196 - race condition when handling PSK identity hint[1.0.1e-51]- fix the CVE-2015-1791 fix (broken server side renegotiation)[1.0.1e-50]- improved fix for CVE-2015-1791- add missing parts of CVE-2015-0209 fix for corectness although unexploitable[1.0.1e-49]- fix CVE-2014-8176 - invalid free in DTLS buffering code- fix CVE-2015-1789 - out-of-bounds read in X509_cmp_time- fix CVE-2015-1790 - PKCS7 crash with missing EncryptedContent- fix CVE-2015-1791 - race condition handling NewSessionTicket- fix CVE-2015-1792 - CMS verify infinite loop with unknown hash function[1.0.1e-48]- fix CVE-2015-3216 - regression in RAND locking that can cause segfaults on read in multithreaded applications[1.0.1e-47]- fix CVE-2015-4000 - prevent the logjam attack on client - restrict the DH key size to at least 768 bits (limit will be increased in future)[1.0.1e-46]- drop the AES-GCM restriction of 2^32 operations because the IV is always 96 bits (32 bit fixed field + 64 bit invocation field)[1.0.1e-45]- update fix for CVE-2015-0287 to what was released upstream[1.0.1e-44]- fix CVE-2015-0209 - potential use after free in d2i_ECPrivateKey()- fix CVE-2015-0286 - improper handling of ASN.1 boolean comparison- fix CVE-2015-0287 - ASN.1 structure reuse decoding memory corruption- fix CVE-2015-0288 - X509_to_X509_REQ NULL pointer dereference- fix CVE-2015-0289 - NULL dereference decoding invalid PKCS#7 data- fix CVE-2015-0292 - integer underflow in base64 decoder- fix CVE-2015-0293 - triggerable assert in SSLv2 server[1.0.1e-43]- fix broken error detection when unwrapping unpadded key[1.0.1e-42.1]- fix the RFC 5649 for key material that does not need padding"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2617");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2617.html");
script_cve_id("CVE-2015-3194","CVE-2015-3195","CVE-2015-3196");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~51.el7_2.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~51.el7_2.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-libs", rpm:"openssl-libs~1.0.1e~51.el7_2.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~51.el7_2.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~51.el7_2.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~42.el6_7.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~42.el6_7.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~42.el6_7.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~42.el6_7.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

