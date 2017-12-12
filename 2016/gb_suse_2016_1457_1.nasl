###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1457_1.nasl 8047 2017-12-08 08:56:07Z santu $
#
# SuSE Update for cyrus-imapd SUSE-SU-2016:1457-1 (cyrus-imapd)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851323");
  script_version("$Revision: 8047 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:56:07 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-06-03 16:25:07 +0530 (Fri, 03 Jun 2016)");
  script_cve_id("CVE-2014-3566", "CVE-2015-8076", "CVE-2015-8077", "CVE-2015-8078");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for cyrus-imapd SUSE-SU-2016:1457-1 (cyrus-imapd)");
  script_tag(name: "summary", value: "Check the version of cyrus-imapd");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  - Previous versions of cyrus-imapd would not allow its users to disable
  old protocols like SSLv1 and SSLv2 that are unsafe due to various known
  attacks like BEAST and POODLE.
  https://bugzilla.cyrusimap.org/show_bug.cgi?id=3867 remedies this issue
  by adding the configuration option 'tls_versions' to the imapd.conf
  file.Note that users who upgrade existing installation of this package
  will *not* have their imapd.conf file overwritten, i.e. their IMAP
  server will continue to support SSLv1 and SSLv2 like before. To disable
  support for those protocols, it's necessary to edit imapd.conf manually
  to state 'tls_versions: tls1_0 tls1_1 tls1_2'. New installations,
  however, will have an imapd.conf file that contains these settings
  already, i.e. newly installed IMAP servers do *not* support SSLv1 and
  SSLv2 unless that support is explicitly enabled by the user. (bsc#901748)
  - An integer overflow vulnerability in cyrus-imapd's urlfetch range
  checking code was fixed. (CVE-2015-8076, CVE-2015-8077, CVE-2015-8078,
  bsc#981670, bsc#954200, bsc#954201)
  
  - Support for Elliptic Curve Diffie-Hellman (ECDH) has been added to
  cyrus-imapd. (bsc#860611).");
  script_tag(name: "affected", value: "cyrus-imapd on SUSE Linux Enterprise Server 12");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "SUSE-SU", value: "2016:1457_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"cyrus-imapd-debuginfo", rpm:"cyrus-imapd-debuginfo~2.3.18~37.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cyrus-imapd-debugsource", rpm:"cyrus-imapd-debugsource~2.3.18~37.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Cyrus-IMAP", rpm:"perl-Cyrus-IMAP~2.3.18~37.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Cyrus-IMAP-debuginfo", rpm:"perl-Cyrus-IMAP-debuginfo~2.3.18~37.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Cyrus-SIEVE-managesieve", rpm:"perl-Cyrus-SIEVE-managesieve~2.3.18~37.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Cyrus-SIEVE-managesieve-debuginfo", rpm:"perl-Cyrus-SIEVE-managesieve-debuginfo~2.3.18~37.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
