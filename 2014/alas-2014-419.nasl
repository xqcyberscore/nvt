# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-419.nasl 6750 2017-07-18 09:56:47Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120078");
script_version("$Revision: 6750 $");
script_tag(name:"creation_date", value:"2015-09-08 13:16:55 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-419");
script_tag(name: "insight", value: "GNU Bash through 4.3 bash43-025 processes trailing strings after certain malformed function definitions in the values of environment variables, which allows remote attackers to write to files or possibly have unknown other impact via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271  and this bulletin is a follow-up to ALAS-2014-418.It was discovered that the fixed-sized redir_stack could be forced to overflow in the Bash parser, resulting in memory corruption, and possibly leading to arbitrary code execution when evaluating untrusted input that would not otherwise be run as code. An off-by-one error was discovered in the way Bash was handling deeply nested flow control constructs. Depending on the layout of the .bss segment, this could allow arbitrary execution of code that would not otherwise be executed by Bash. Special notes:Because of the exceptional nature of this security event, we have backfilled our 2014.03, 2013.09, and 2013.03 Amazon Linux AMI repositories with new bash packages that also fix both CVE-2014-7169  and CVE-2014-6271 .For 2014.09 Amazon Linux AMIs, bash-4.1.2-15.21.amzn1 addresses both CVEs.  Running yum clean all followed by yum update bash will install the fixed package.For Amazon Linux AMIs locked to the 2014.03 repositories, bash-4.1.2-15.21.amzn1 also addresses both CVEs.  Running yum clean all followed by yum update bash will install the fixed package.For Amazon Linux AMIs locked to the 2013.09 or 2013.03 repositories, bash-4.1.2-15.18.22.amzn1 addresses both CVEs.  Running yum clean all followed by yum update bash will install the fixed package.For Amazon Linux AMIs locked to the 2012.09, 2012.03, or 2011.09 repositories, run yum clean all followed by yum --releasever=2013.03 update bash to install only the updated bash package.If you are using a pre-2011.09 Amazon Linux AMI, then you are using a version of the Amazon Linux AMI that was part of our public beta, and we encourage you to move to a newer version of the Amazon Linux AMI as soon as possible."); 
script_tag(name : "solution", value : "Run yum update bash to update your system.  Note that you may need to run yum clean all first.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-419.html");
script_cve_id("CVE-2014-7186", "CVE-2014-7169", "CVE-2014-7187");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"bash-debuginfo", rpm:"bash-debuginfo~4.1.2~15.21.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"bash-doc", rpm:"bash-doc~4.1.2~15.21.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"bash", rpm:"bash~4.1.2~15.21.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
