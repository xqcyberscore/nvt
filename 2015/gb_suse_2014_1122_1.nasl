###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1122_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for glibc SUSE-SU-2014:1122-1 (glibc)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850912");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-16 14:10:31 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2012-4412", "CVE-2013-0242", "CVE-2013-4237", "CVE-2013-4332", "CVE-2013-4788", "CVE-2014-4043", "CVE-2014-5119");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for glibc SUSE-SU-2014:1122-1 (glibc)");
  script_tag(name: "summary", value: "Check the version of glibc");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This glibc update fixes a critical privilege escalation vulnerability and
  the following security and non-security issues:

  * bnc#892073: An off-by-one error leading to a heap-based buffer
  overflow was found in __gconv_translit_find(). An exploit that
  targets the problem is publicly available. (CVE-2014-5119)
  * bnc#886416: Avoid redundant shift character in iconv output at block
  boundary.
  * bnc#883022: Initialize errcode in sysdeps/unix/opendir.c.
  * bnc#882600: Copy filename argument in
  posix_spawn_file_actions_addopen. (CVE-2014-4043)
  * bnc#864081: Take lock in pthread_cond_wait cleanup handler only when
  needed.
  * bnc#843735: Don't crash on unresolved weak symbol reference.
  * bnc#839870: Fix integer overflows in malloc. (CVE-2013-4332)
  * bnc#836746: Avoid race between {,__de}allocate_stack and
  __reclaim_stacks during fork.
  * bnc#834594: Fix readdir_r with long file names. (CVE-2013-4237)
  * bnc#830268: Initialize pointer guard also in static executables.
  (CVE-2013-4788)
  * bnc#801246: Fix buffer overrun in regexp matcher. (CVE-2013-0242)
  * bnc#779320: Fix buffer overflow in strcoll. (CVE-2012-4412)
  * bnc#750741: Use absolute timeout in x86 pthread_cond_timedwait.

  Security Issues:

  * CVE-2014-5119
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-5119 
  * CVE-2014-4043
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4043 
  * CVE-2012-4412
  http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-4412 
  * CVE-2013-0242
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-0242 
  * CVE-2013-4788
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4788 
  * CVE-2013-4237
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4237 
  * CVE-2013-4332
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4332");
  script_tag(name: "affected", value: "glibc on SUSE Linux Enterprise Server 11 SP1 LTSS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:1122_1");
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

if(release == "SLES11.0SP1")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-locale-32bit", rpm:"glibc-locale-32bit~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.11.1~0.58.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
