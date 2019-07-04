###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 4194-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704194");
  script_version("2019-07-04T09:25:28+0000");
  script_cve_id("CVE-2018-1308");
  script_name("Debian Security Advisory DSA 4194-1 (lucene-solr - security update)");
  script_tag(name:"last_modification", value:"2019-07-04 09:25:28 +0000 (Thu, 04 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-05-06 00:00:00 +0200 (Sun, 06 May 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4194.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB[89]");
  script_tag(name:"affected", value:"lucene-solr on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), this problem has been fixed
in version 3.6.2+dfsg-5+deb8u2.

For the stable distribution (stretch), this problem has been fixed in
version 3.6.2+dfsg-10+deb9u2.

We recommend that you upgrade your lucene-solr packages.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/lucene-solr");
  script_tag(name:"summary", value:"An XML external entity expansion vulnerability was discovered in the
DataImportHandler of Solr, a search server based on Lucene, which could
result in information disclosure.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"liblucene3-contrib-java", ver:"3.6.2+dfsg-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblucene3-java", ver:"3.6.2+dfsg-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblucene3-java-doc", ver:"3.6.2+dfsg-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsolr-java", ver:"3.6.2+dfsg-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"solr-common", ver:"3.6.2+dfsg-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"solr-jetty", ver:"3.6.2+dfsg-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"solr-tomcat", ver:"3.6.2+dfsg-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblucene3-contrib-java", ver:"3.6.2+dfsg-10+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblucene3-java", ver:"3.6.2+dfsg-10+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblucene3-java-doc", ver:"3.6.2+dfsg-10+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsolr-java", ver:"3.6.2+dfsg-10+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"solr-common", ver:"3.6.2+dfsg-10+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"solr-jetty", ver:"3.6.2+dfsg-10+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"solr-tomcat", ver:"3.6.2+dfsg-10+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}