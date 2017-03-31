# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-276.nasl 4514 2016-11-15 10:04:28Z cfi $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120568");
script_version("$Revision: 4514 $");
script_tag(name:"creation_date", value:"2015-09-08 13:29:45 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2016-11-15 11:04:28 +0100 (Tue, 15 Nov 2016) $");
script_name("Amazon Linux Local Check: ALAS-2014-276");
script_tag(name: "insight", value: "Varnish before 3.0.5 allows remote attackers to cause a denial of service (child-process crash and temporary caching outage) via a GET request with trailing whitespace characters and no URI.varnish 3.0.3 uses world-readable permissions for the /var/log/varnish/ directory and the log files in the directory, which allows local users to obtain sensitive information by reading the files. NOTE: some of these details are obtained from third party information."); 
script_tag(name : "solution", value : "Run yum update varnish to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-276.html");
script_cve_id("CVE-2013-4484", "CVE-2013-0345");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("HostDetails/OS/cpe:/o:amazon:linux", "login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_summary("Amazon Linux Local Security Checks ALAS-2014-276");
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
if ((res = isrpmvuln(pkg:"varnish-debuginfo", rpm:"varnish-debuginfo~3.0.5~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"varnish-docs", rpm:"varnish-docs~3.0.5~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"varnish-libs-devel", rpm:"varnish-libs-devel~3.0.5~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"varnish-libs", rpm:"varnish-libs~3.0.5~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"varnish", rpm:"varnish~3.0.5~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
