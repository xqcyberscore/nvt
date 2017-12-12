###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1574_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for clamav SUSE-SU-2014:1574-1 (clamav)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.850812");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2013-6497", "CVE-2014-9050");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for clamav SUSE-SU-2014:1574-1 (clamav)");
  script_tag(name: "summary", value: "Check the version of clamav");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  clamav was updated to version 0.98.5 to fix three security issues and
  several non-security issues.

  These security issues have been fixed:

  * Crash when scanning maliciously crafted yoda's crypter files
  (CVE-2013-6497).
  * Heap-based buffer overflow when scanning crypted PE files
  (CVE-2014-9050).
  * Crash when using 'clamscan -a'.

  These non-security issues have been fixed:

  * Support for the XDP file format and extracting, decoding, and
  scanning PDF files within XDP files.
  * Addition of shared library support for LLVM versions 3.1 - 3.5 for
  the purpose of just-in-time(JIT) compilation of ClamAV bytecode
  signatures.
  * Enhancements to the clambc command line utility to assist ClamAV
  bytecode signature authors by providing introspection into compiled
  bytecode programs.
  * Resolution of many of the warning messages from ClamAV compilation.
  * Improved detection of malicious PE files.
  * ClamAV 0.98.5 now works with OpenSSL in FIPS compliant mode
  (bnc#904207).
  * Fix server socket setup code in clamd (bnc#903489).
  * Change updateclamconf to prefer the state of the old config file
  even for commented-out options (bnc#903719).
  * Fix infinite loop in clamdscan when clamd is not running.
  * Fix buffer underruns when handling multi-part MIME email attachments.
  * Fix configuration of OpenSSL on various platforms.
  * Fix linking issues with libclamunrar.

  Security Issues:

  * CVE-2013-6497
 http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-6497 
  * CVE-2014-9050
 http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9050");
  script_tag(name: "affected", value: "clamav on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:1574_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "SLES11.0SP3")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.5~0.5.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
