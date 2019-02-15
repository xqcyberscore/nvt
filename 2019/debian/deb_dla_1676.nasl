# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891676");
  script_version("$Revision: 13675 $");
  script_cve_id("CVE-2017-15105");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1676-1] unbound security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 07:44:05 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-15 00:00:00 +0100 (Fri, 15 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://unbound.net/downloads/CVE-2017-15105.txt");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00022.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8\.[0-9]+");
  script_tag(name:"affected", value:"unbound on Debian Linux");
  script_tag(name:"insight", value:"Unbound is a recursive-only caching DNS server which can perform DNSSEC
validation of results. It implements only a minimal amount of authoritative
service to prevent leakage to the root nameservers: forward lookups for
localhost, reverse for 127.0.0.1 and ::1, and NXDOMAIN for zones served by
AS112. Stub and forward zones are supported.");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
1.4.22-3+deb8u4.

We recommend that you upgrade your unbound packages.");
  script_tag(name:"summary", value:"Ralph Dolmans and Karst Koymans found a flaw in the way unbound, a
validating, recursive, caching DNS resolver, validated
wildcard-synthesized NSEC records.

An improperly validated wildcard NSEC record could be used to prove the
non-existence (NXDOMAIN answer) of an existing wildcard record, or trick
unbound into accepting a NODATA proof.

For more information please refer to the linked upstream advisory.");

  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libunbound-dev", ver:"1.4.22-3+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libunbound2", ver:"1.4.22-3+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-unbound", ver:"1.4.22-3+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"unbound", ver:"1.4.22-3+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"unbound-anchor", ver:"1.4.22-3+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"unbound-host", ver:"1.4.22-3+deb8u4", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
