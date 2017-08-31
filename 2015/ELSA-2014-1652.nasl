# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1652.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123280");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:01:41 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1652");
script_tag(name: "insight", value: "ELSA-2014-1652 -  openssl security update - [1.0.1e-30.2]- fix CVE-2014-3567 - memory leak when handling session tickets- fix CVE-2014-3513 - memory leak in srtp support- add support for fallback SCSV to partially mitigate CVE-2014-3566 (padding attack on SSL3)[1.0.1e-30]- add ECC TLS extensions to DTLS (#1119800)[1.0.1e-29]- fix CVE-2014-3505 - doublefree in DTLS packet processing- fix CVE-2014-3506 - avoid memory exhaustion in DTLS- fix CVE-2014-3507 - avoid memory leak in DTLS- fix CVE-2014-3508 - fix OID handling to avoid information leak- fix CVE-2014-3509 - fix race condition when parsing server hello- fix CVE-2014-3510 - fix DoS in anonymous (EC)DH handling in DTLS- fix CVE-2014-3511 - disallow protocol downgrade via fragmentation[1.0.1e-28]- fix CVE-2014-0224 fix that broke EAP-FAST session resumption support[1.0.1e-26]- drop EXPORT, RC2, and DES from the default cipher list (#1057520)- print ephemeral key size negotiated in TLS handshake (#1057715)- do not include ECC ciphersuites in SSLv2 client hello (#1090952)- properly detect encryption failure in BIO (#1100819)- fail on hmac integrity check if the .hmac file is empty (#1105567)- FIPS mode: make the limitations on DSA, DH, and RSA keygen length enforced only if OPENSSL_ENFORCE_MODULUS_BITS environment variable is set[1.0.1e-25]- fix CVE-2010-5298 - possible use of memory after free- fix CVE-2014-0195 - buffer overflow via invalid DTLS fragment- fix CVE-2014-0198 - possible NULL pointer dereference- fix CVE-2014-0221 - DoS from invalid DTLS handshake packet- fix CVE-2014-0224 - SSL/TLS MITM vulnerability- fix CVE-2014-3470 - client-side DoS when using anonymous ECDH[1.0.1e-24]- add back support for secp521r1 EC curve[1.0.1e-23]- fix CVE-2014-0160 - information disclosure in TLS heartbeat extension[1.0.1e-22]- use 2048 bit RSA key in FIPS selftests[1.0.1e-21]- add DH_compute_key_padded needed for FIPS CAVS testing- make 3des strength to be 128 bits instead of 168 (#1056616)- FIPS mode: do not generate DSA keys and DH parameters < 2048 bits- FIPS mode: use approved RSA keygen (allows only 2048 and 3072 bit keys)- FIPS mode: add DH selftest- FIPS mode: reseed DRBG properly on RAND_add()- FIPS mode: add RSA encrypt/decrypt selftest- FIPS mode: add hard limit for 2^32 GCM block encryptions with the same key- use the key length from configuration file if req -newkey rsa is invoked[1.0.1e-20]- fix CVE-2013-4353 - Invalid TLS handshake crash[1.0.1e-19]- fix CVE-2013-6450 - possible MiTM attack on DTLS1[1.0.1e-18]- fix CVE-2013-6449 - crash when version in SSL structure is incorrect[1.0.1e-17]- add back some no-op symbols that were inadvertently dropped"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1652");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1652.html");
script_cve_id("CVE-2014-3513","CVE-2014-3567");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~34.el7_0.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~34.el7_0.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-libs", rpm:"openssl-libs~1.0.1e~34.el7_0.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~34.el7_0.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~34.el7_0.6", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~30.el6_6.2", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~1.0.1e~30.el6_6.2", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.0.1e~30.el6_6.2", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssl-static", rpm:"openssl-static~1.0.1e~30.el6_6.2", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

