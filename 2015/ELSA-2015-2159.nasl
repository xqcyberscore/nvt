# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2159.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122761");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:33 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2159");
script_tag(name: "insight", value: "ELSA-2015-2159 -  curl security, bug fix, and enhancement update - [7.29.0-25.0.1]- disable check to make build pass[7.29.0-25]- fix spurious failure of test 1500 on ppc64le (#1218272)[7.29.0-24]- use the default min/max TLS version provided by NSS (#1170339)- improve handling of timeouts and blocking direction to speed up FTP (#1218272)[7.29.0-23]- require credentials to match for NTLM re-use (CVE-2015-3143)- close Negotiate connections when done (CVE-2015-3148)[7.29.0-22]- reject CRLFs in URLs passed to proxy (CVE-2014-8150)[7.29.0-21]- use only full matches for hosts used as IP address in cookies (CVE-2014-3613)- fix handling of CURLOPT_COPYPOSTFIELDS in curl_easy_duphandle (CVE-2014-3707)[7.29.0-20]- eliminate unnecessary delay when resolving host from /etc/hosts (#1130239)- allow to enable/disable new AES cipher-suites (#1066065)- call PR_Cleanup() on curl tool exit if NSPR is used (#1071254)- implement non-blocking TLS handshake (#1091429)- fix limited connection re-use for unencrypted HTTP (#1101092)- disable libcurl-level downgrade to SSLv3 (#1154060)- include response headers added by proxy in CURLINFO_HEADER_SIZE (#1161182)- ignore CURLOPT_FORBID_REUSE during NTLM HTTP auth (#1166264)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2159");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2159.html");
script_cve_id("CVE-2014-3613","CVE-2014-3707","CVE-2014-8150","CVE-2015-3143","CVE-2015-3148");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
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
  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~25.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~25.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.29.0~25.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

