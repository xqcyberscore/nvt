# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0436.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131107");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-11-08 13:02:04 +0200 (Sun, 08 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0436");
script_tag(name: "insight", value: "Updated krb5 packages fix security vulnerabilities: In MIT krb5 1.5 and later, applications which call gss_inquire_context() on a partially-established SPNEGO context can cause the GSS-API library to read from a pointer using the wrong type, generally causing a process crash. This bug may go unnoticed, because the most common SPNEGO authentication scenario establishes the context after just one call to gss_accept_sec_context(). Java server applications using the native JGSS provider are vulnerable to this bug. A carefully crafted SPNEGO packet might allow the gss_inquire_context() call to succeed with attacker-determined results, but applications should not make access control decisions based on gss_inquire_context() results prior to context establishment (CVE-2015-2695). In MIT krb5 1.9 and later, applications which call gss_inquire_context() on a partially-established IAKERB context can cause the GSS-API library to read from a pointer using the wrong type, generally causing a process crash. Java server applications using the native JGSS provider are vulnerable to this bug. A carefully crafted IAKERB packet might allow the gss_inquire_context() call to succeed with attacker-determined results, but applications should not make access control decisions based on gss_inquire_context() results prior to context establishment (CVE-2015-2696). In MIT krb5 1.7 and later, an authenticated attacker may be able to cause a KDC to crash using a TGS request with a large realm field beginning with a null byte. If the KDC attempts to find a referral to answer the request, it constructs a principal name for lookup using krb5_build_principal() with the requested realm. Due to a bug in this function, the null byte causes only one byte be allocated for the realm field of the constructed principal, far less than its length. Subsequent operations on the lookup principal may cause a read beyond the end of the mapped memory region, causing the KDC process to crash (CVE-2015-2697)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0436.html");
script_cve_id("CVE-2015-2695","CVE-2015-2696","CVE-2015-2697");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0436");
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
if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.12.2~8.1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
