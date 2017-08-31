# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2016-676.nasl 6574 2017-07-06 13:41:26Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.120666");
script_version("$Revision: 6574 $");
script_tag(name:"creation_date", value:"2016-03-31 08:02:09 +0300 (Thu, 31 Mar 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:41:26 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2016-676");
script_tag(name: "insight", value: "It was found that when an SVN server (both svnserve and httpd with the mod_dav_svn module) searched the history of a file or a directory, it would disclose its location in the repository if that file or directory was not readable (for example, if it had been moved). (CVE-2015-3187 )An integer overflow was discovered allowing remote attackers to execute arbitrary code via an svn:// protocol string, which triggers a heap-based buffer overflow and an out-of-bounds read. (CVE-2015-5259 )It was found that the mod_authz_svn module did not properly restrict anonymous access to Subversion repositories under certain configurations when used with Apache httpd 2.4.x. This could allow a user to anonymously access files in a Subversion repository, which should only be accessible to authenticated users. (CVE-2015-3184 )It was found that the mod_dav_svn module was vulnerable to a remotely triggerable heap-based buffer overflow and out-of-bounds read caused by an integer overflow when parsing skel-encoded request bodies, allowing an attacker with write access to a repository to cause a denial of service attack (on 32-bit or 64-bit servers) or possibly execute arbitrary code (on 32-bit servers only) under the context of the httpd process. (CVE-2015-5343 )");
script_tag(name : "solution", value : "Run yum update mod_dav_svn to update your system.
                                    Run yum update subversion to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2016-676.html");
script_cve_id("CVE-2015-3187","CVE-2015-5259","CVE-2015-3184","CVE-2015-5343");
script_tag(name:"cvss_base", value:"9.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
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
if ((res = isrpmvuln(pkg:"svn", rpm:"svn~1.8.15~1.52.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"svn-debuginfo", rpm:"svn-debuginfo~1.8.15~1.52.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"svn", rpm:"svn~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"subversion-tools", rpm:"subversion-tools~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"subversion", rpm:"subversion~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"subversion-python27", rpm:"subversion-python27~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"subversion-javahl", rpm:"subversion-javahl~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"subversion-ruby", rpm:"subversion-ruby~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"subversion-perl", rpm:"subversion-perl~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"subversion-debuginfo", rpm:"subversion-debuginfo~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"subversion-devel", rpm:"subversion-devel~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"subversion-libs", rpm:"subversion-libs~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"subversion-python26", rpm:"subversion-python26~1.8.15~1.54.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
