# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0427.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131115");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-11-08 13:02:10 +0200 (Sun, 08 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0427");
script_tag(name: "insight", value: "Several flaws were found in the processing of malformed web content. A web page containing malicious content could cause Firefox to crash or, potentially, execute arbitrary code with the privileges of the user running Firefox. (CVE-2015-4513, CVE-2015-7189, CVE-2015-7194, CVE-2015-7196, CVE-2015-7198, CVE-2015-7197) A same-origin policy bypass flaw was found in the way Firefox handled certain cross-origin resource sharing (CORS) requests. A web page containing malicious content could cause Firefox to disclose sensitive information. (CVE-2015-7193) A same-origin policy bypass flaw was found in the way Firefox handled URLs containing IP addresses with white-space characters. This could lead to cross-site scripting attacks. (CVE-2015-7188) A use-after-poison flaw and a heap-based buffer overflow flaw were found in the way NSS parsed certain ASN.1 structures. An attacker could use these flaws to cause NSS to crash or execute arbitrary code with the permissions of the user running an application compiled against the NSS library. (CVE-2015-7181, CVE-2015-7182) A heap-based buffer overflow was found in NSPR. An attacker could use this flaw to cause NSPR to crash or execute arbitrary code with the permissions of the user running an application compiled against the NSPR library. (CVE-2015-7183) Note: Applications using NSPR's PL_ARENA_ALLOCATE, PR_ARENA_ALLOCATE, PL_ARENA_GROW, or PR_ARENA_GROW macros need to be rebuilt against the fixed nspr packages to completely resolve the CVE-2015-7183 issue."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0427.html");
script_cve_id("CVE-2015-4513","CVE-2015-7181","CVE-2015-7182","CVE-2015-7183","CVE-2015-7188","CVE-2015-7189","CVE-2015-7193","CVE-2015-7194","CVE-2015-7196","CVE-2015-7197","CVE-2015-7198");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0427");
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
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.4.0~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~38.4.0~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.10.10~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.20.1~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"rootcerts", rpm:"rootcerts~20151029.00~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
