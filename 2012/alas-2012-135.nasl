# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-135.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120334");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:23:48 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2012-135");
script_tag(name: "insight", value: "Directory traversal vulnerability in lib/puppet/reports/store.rb in Puppet before 2.6.17 and 2.7.x before 2.7.18, and Puppet Enterprise before 2.5.2, when Delete is enabled in auth.conf, allows remote authenticated users to delete arbitrary files on the puppet master server via a .. (dot dot) in a node name. Puppet before 2.6.17 and 2.7.x before 2.7.18, and Puppet Enterprise before 2.5.2, allows remote authenticated users to read arbitrary files on the puppet master server by leveraging an arbitrary user's certificate and private key in a GET request. lib/puppet/ssl/certificate_authority.rb in Puppet before 2.6.17 and 2.7.x before 2.7.18, and Puppet Enterprise before 2.5.2, does not properly restrict the characters in the Common Name field of a Certificate Signing Request (CSR), which makes it easier for user-assisted remote attackers to trick administrators into signing a crafted agent certificate via ANSI control sequences. lib/puppet/defaults.rb in Puppet 2.7.x before 2.7.18, and Puppet Enterprise before 2.5.2, uses 0644 permissions for last_run_report.yaml, which allows local users to obtain sensitive configuration information by leveraging access to the puppet master server to read this file."); 
script_tag(name : "solution", value : "Run yum update puppet to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-135.html");
script_cve_id("CVE-2012-3865", "CVE-2012-3864", "CVE-2012-3867", "CVE-2012-3866");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
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
if ((res = isrpmvuln(pkg:"puppet-server", rpm:"puppet-server~2.7.18~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"puppet-debuginfo", rpm:"puppet-debuginfo~2.7.18~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"puppet", rpm:"puppet~2.7.18~1.9.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
