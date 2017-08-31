# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-461.nasl 6715 2017-07-13 09:57:40Z teissa $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org 
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
script_oid("1.3.6.1.4.1.25623.1.0.120100");
script_version("$Revision: 6715 $");
script_tag(name:"creation_date", value:"2015-09-08 13:17:24 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-461");
script_tag(name: "insight", value: "Path traversal attacks are possible in the processing of absolute symlinks. In checking symlinks for traversals, only relative links were considered. This allowed path traversals to exist where they should have otherwise been prevented. This was exploitable via both archive extraction and through volume mounts.  This vulnerability allowed malicious images or builds from malicious Dockerfiles to write files to the host system and escape containerization, leading to privilege escalation.  (CVE-2014-9356 )It has been discovered that the introduction of chroot for archive extraction in Docker 1.3.2 had introduced a privilege escalation vulnerability. Malicious images or builds from malicious Dockerfiles could escalate privileges and execute arbitrary code as a root user on the Docker host by providing a malicious 'xz' binary.  (CVE-2014-9357 )It has been discovered that Docker does not sufficiently validate Image IDs as provided either via 'docker load' or through registry communications. This allows for path traversal attacks, causing graph corruption and manipulation by malicious images, as well as repository spoofing attacks. (CVE-2014-9358 )"); 
script_tag(name : "solution", value : "Run yum update docker to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-461.html");
script_cve_id("CVE-2014-9357", "CVE-2014-9356", "CVE-2014-9358");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:N");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_copyright("Eero Volotinen");
script_family("Amazon Linux Local Security Checks");
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
if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"docker", rpm:"docker~1.3.3~1.0.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~1.3.3~1.0.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"docker-pkg-devel", rpm:"docker-pkg-devel~1.3.3~1.0.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
