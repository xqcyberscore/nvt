# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1666.nasl 6552 2017-07-06 11:49:41Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122866");
script_version("$Revision: 6552 $");
script_tag(name:"creation_date", value:"2016-02-05 14:01:36 +0200 (Fri, 05 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:49:41 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1666");
script_tag(name: "insight", value: "ELSA-2015-1666 -  httpd24-httpd security update - [2.4.12-6.0.1.el7.1]- replace index.html with Oracles index page oracle_index.html- update vstring in specfile[2.4.12-6.1]- core: fix chunk header parsing defect (CVE-2015-3183)- core: replace of ap_some_auth_required with ap_some_authn_required and ap_force_authn hook (CVE-2015-3185)- core: fix pointer dereference crash with ErrorDocument 400 pointing to a local URL-path (CVE-2015-0253)- mod_lua: fix possible mod_lua crash due to websocket bug (CVE-2015-0228)[2.4.12-6]- remove old sslsninotreq patch (#1199040)[2.4.12-5]- fix wrong path to document root in httpd.conf (#1196559)[2.4.12-4]- fix SELinux context of httpd-scl-wrapper (#1193456)[2.4.12-3]- include apr_skiplist and build against system APR/APR-util (#1187646)[2.4.12-2]- rebuild against new APR/APR-util (#1187646)[2.4.12-1]- update to version 2.4.12- fix possible crash in SIGINT handling (#1184034)[2.4.10-2]- allow enabling additional SCLs using service-environment file- enable mod_request by default for mod_auth_form- move disabled-by-default modules from 00-base.conf to 00-optional.conf[2.4.10-1]- update to 2.4.10- remove mod_proxy_html obsolete (#1174790)- remove dbmmanage from httpd-tools (#1151375)- add slash before root_libexecdir macro (#1149076)- ab: fix integer overflow when printing stats with lot of requests (#1091650)- mod_ssl: use 2048-bit RSA key with SHA-256 signature in dummy certificate (#1079925)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1666");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1666.html");
script_cve_id("CVE-2015-0228","CVE-2015-0253","CVE-2015-3183","CVE-2015-3185");
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
  if ((res = isrpmvuln(pkg:"httpd24-httpd", rpm:"httpd24-httpd~2.4.12~6.0.1.el7.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd24-httpd-devel", rpm:"httpd24-httpd-devel~2.4.12~6.0.1.el7.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd24-httpd-manual", rpm:"httpd24-httpd-manual~2.4.12~6.0.1.el7.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd24-httpd-tools", rpm:"httpd24-httpd-tools~2.4.12~6.0.1.el7.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd24-mod_ldap", rpm:"httpd24-mod_ldap~2.4.12~6.0.1.el7.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd24-mod_proxy_html", rpm:"httpd24-mod_proxy_html~2.4.12~6.0.1.el7.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd24-mod_session", rpm:"httpd24-mod_session~2.4.12~6.0.1.el7.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"httpd24-mod_ssl", rpm:"httpd24-mod_ssl~2.4.12~6.0.1.el7.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

