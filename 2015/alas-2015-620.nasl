# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-620.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120610");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-12-15 02:51:23 +0200 (Tue, 15 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2015-620");
script_tag(name: "insight", value: "A directory traversal flaw was found in the strip and objcopy utilities. A specially crafted file could cause strip or objdump to overwrite an arbitrary file writable by the user running either of these utilities.A buffer overflow flaw was found in the way various binutils utilities processed certain files. If a user were tricked into processing a specially crafted file, it could cause the utility used to process that file to crash or, potentially, execute arbitrary code with the privileges of the user running that utility.An integer overflow flaw was found in the way the strings utility processed certain files. If a user were tricked into running the strings utility on a specially crafted file, it could cause the strings executable to crash.A stack-based buffer overflow flaw was found in the SREC parser of the libbfd library. A specially crafted file could cause an application using the libbfd library to crash or, potentially, execute arbitrary code with the privileges of the user running that application.A heap-based buffer overflow flaw was found in the way certain binutils utilities processed archive files. If a user were tricked into processing a specially crafted archive file, it could cause the utility used to process that archive to crash or, potentially, execute arbitrary code with the privileges of the user running that utility.A stack-based buffer overflow flaw was found in the way various binutils utilities processed certain files. If a user were tricked into processing a specially crafted file, it could cause the utility used to process that file to crash or, potentially, execute arbitrary code with the privileges of the user running that utility.A stack-based buffer overflow flaw was found in the way objdump processed IHEX files. A specially crafted IHEX file could cause objdump to crash or, potentially, execute arbitrary code with the privileges of the user running objdump.It was found that the fix for the CVE-2014-8485  issue was incomplete: a heap-based buffer overflow in the objdump utility could cause it to crash or, potentially, execute arbitrary code with the privileges of the user running objdump when processing specially crafted files."); 
script_tag(name : "solution", value : "Run yum update binutils to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-620.html");
script_cve_id("CVE-2014-8737","CVE-2014-8485","CVE-2014-8484","CVE-2014-8504","CVE-2014-8738","CVE-2014-8501","CVE-2014-8503","CVE-2014-8502");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.23.52.0.1~55.65.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"binutils-debuginfo", rpm:"binutils-debuginfo~2.23.52.0.1~55.65.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.23.52.0.1~55.65.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
