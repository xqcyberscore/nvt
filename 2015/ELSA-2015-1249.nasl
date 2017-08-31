# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1249.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123063");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:58:53 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1249");
script_tag(name: "insight", value: "ELSA-2015-1249 -  httpd security, bug fix, and enhancement update - [2.2.15-45.0.1]- replace index.html with Oracle's index page oracle_index.html- update vstring in specfile[2.2.15-45]- mod_proxy_balancer: add support for 'drain mode' (N) (#767130)[2.2.15-44]- set SSLCipherSuite to DEFAULT:!EXP:!SSLv2:!DES:!IDEA:!SEED:+3DES (#1086771)[2.2.15-43]- revert DirectoryMatch patch from 2.2.15-40 (#1016963)[2.2.15-42]- core: fix bypassing of mod_headers rules via chunked requests (CVE-2013-5704)[2.2.15-41]- fix compilation with older OpenSSL caused by misspelling in patch (#1162268)[2.2.15-40]- mod_proxy: do not mix workers shared memory during graceful restart (#1149906)- mod_ssl: Fix SSL_CLIENT_VERIFY value when optional_no_ca and SSLSessionCache are used and SSL session is resumed (#1149703)- mod_ssl: log revoked certificates at the INFO level (#1161328)- mod_ssl: use -extensions v3_req for certificate generation (#906476)- core: check the config file before restarting the server (#1146194)- core: do not match files when using DirectoryMatch (#1016963)- core: improve error message for inaccessible DocumentRoot (#987590)- rotatelogs: improve support for localtime (#922844)- mod_deflate: fix decompression of files larger than 4GB (#1057695)- ab: fix integer overflow when printing stats with lot of requests (#1092419)- ab: try all addresses instead of failing on first one when not available (#1125269)- ab: fix read failure when targeting SSL server (#1045477)- apachectl: support HTTPD_LANG variable from /etc/sysconfig/httpd (#963146)- do not display 'bomb' icon for files ending with 'core' (#1069625)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1249");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1249.html");
script_cve_id("CVE-2013-5704");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.15~45.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.15~45.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.15~45.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.15~45.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.15~45.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

