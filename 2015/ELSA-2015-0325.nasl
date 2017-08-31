# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-0325.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123169");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 14:00:15 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-0325");
script_tag(name: "insight", value: "ELSA-2015-0325 -  httpd security, bug fix, and enhancement update - [2.4.6-31.0.1]- replace index.html with Oracle's index page oracle_index.html[2.4.6-31]- mod_proxy_fcgi: determine if FCGI_CONN_CLOSE should be enabled instead of hardcoding it (#1168050)- mod_proxy: support Unix Domain Sockets (#1168081)[2.4.6-30]- core: fix bypassing of mod_headers rules via chunked requests (CVE-2013-5704)- mod_cache: fix NULL pointer dereference on empty Content-Type (CVE-2014-3581)[2.4.6-29]- rebuild against proper version of OpenSSL (#1080125)[2.4.6-28]- set vstring based on /etc/os-release (#1114123)[2.4.6-27]- fix the dependency on openssl-libs to match the fix for #1080125[2.4.6-26]- allow 'es to be seen under virtual hosts (#1131847)[2.4.6-25]- do not use hardcoded curve for ECDHE suites (#1080125)[2.4.6-24]- allow reverse-proxy to be set via SetHandler (#1136290)[2.4.6-23]- fix possible crash in SIGINT handling (#1131006)[2.4.6-22]- ab: fix integer overflow when printing stats with lot of requests (#1092420)[2.4.6-21]- add pre_htaccess so mpm-itk can be build as separate module (#1059143)[2.4.6-20]- mod_ssl: prefer larger keys and support up to 8192-bit keys (#1073078)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-0325");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-0325.html");
script_cve_id("CVE-2013-5704","CVE-2014-3581");
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
  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.6~31.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.4.6~31.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.4.6~31.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.6~31.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mod_ldap", rpm:"mod_ldap~2.4.6~31.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mod_proxy_html", rpm:"mod_proxy_html~2.4.6~31.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mod_session", rpm:"mod_session~2.4.6~31.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.6~31.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

