###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4165.nasl 9594 2018-04-25 02:13:41Z ckuersteiner $
#
# Auto-generated from advisory DSA 4165-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704165");
  script_version("$Revision: 9594 $");
  script_cve_id("CVE-2018-8763", "CVE-2018-8764");
  script_name("Debian Security Advisory DSA 4165-1 (ldap-account-manager - security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 04:13:41 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-03 00:00:00 +0200 (Tue, 03 Apr 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4165.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB[89]\.[0-9]+");
  script_tag(name:"affected", value:"ldap-account-manager on Debian Linux");
  script_tag(name:"insight", value:"LDAP Account Manager (LAM) runs on an existing webserver.
It manages user, group and host accounts. Currently LAM
supports these account types: Samba 3/4, Unix, Kolab 2/3,
address book entries, NIS mail aliases and MAC addresses.
There is an integrated LDAP browser to allow access to the
raw LDAP attributes. You can use templates
for account creation and use multiple configuration profiles.
Account information can be exported as PDF file. There is also
a script included which manages quotas and homedirectories.");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 4.7.1-1+deb8u1.

For the stable distribution (stretch), these problems have been fixed in
version 5.5-1+deb9u1.

We recommend that you upgrade your ldap-account-manager packages.

For the detailed security status of ldap-account-manager please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/ldap-account-manager");
  script_tag(name:"summary",  value:"Michal Kedzior found two vulnerabilities in LDAP Account Manager, a web
front-end for LDAP directories.

CVE-2018-8763 
The found Reflected Cross Site Scripting (XSS) vulnerability might
allow an attacker to execute JavaScript code in the browser of the
victim or to redirect her to a malicious website if the victim clicks
on a specially crafted link.

CVE-2018-8764 
The application leaks the CSRF token in the URL, which can be use by
an attacker to perform a Cross-Site Request Forgery attack, in which
a victim logged in LDAP Account Manager might performed unwanted
actions in the front-end by clicking on a link crafted by the
attacker.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"ldap-account-manager", ver:"5.5-1+deb9u1", rls_regex:"DEB9\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ldap-account-manager-lamdaemon", ver:"5.5-1+deb9u1", rls_regex:"DEB9\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ldap-account-manager", ver:"4.7.1-1+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ldap-account-manager-lamdaemon", ver:"4.7.1-1+deb8u1", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
