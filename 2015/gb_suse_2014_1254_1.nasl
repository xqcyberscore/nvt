###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1254_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for bash openSUSE-SU-2014:1254-1 (bash)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850676");
  script_version("$Revision: 8046 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-09-18 10:31:31 +0200 (Fri, 18 Sep 2015)");
  script_cve_id("CVE-2014-6271", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for bash openSUSE-SU-2014:1254-1 (bash)");
  script_tag(name: "summary", value: "Check the version of bash
  This NVT has been deprecated by because no proper information available
  from advisory link.

  There is also no bash-4.2~75.4.1 on opensuse. complete NVT is wrong.");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  bash was updated to fix command injection via environment variables.
  (CVE-2014-6271,CVE-2014-7169)

  Also a hardening patch was applied that only imports functions over
  BASH_FUNC_ prefixed environment variables.

  Also fixed: CVE-2014-7186, CVE-2014-7187: bad handling of HERE documents
  and for loop issue");
  script_tag(name: "affected", value: "bash on openSUSE 13.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "openSUSE-SU", value: "2014:1254_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  exit(0);
}

exit(66); ## This NVT is deprecated as proper information is not available in
#advisory.
#there is also no bash~4.2~75.4.1 on opensuse.
#the complete NVT is wrong.


include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"bash-debuginfo", rpm:"bash-debuginfo~4.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-debugsource", rpm:"bash-debugsource~4.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-devel", rpm:"bash-devel~4.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-loadables", rpm:"bash-loadables~4.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-loadables-debuginfo", rpm:"bash-loadables-debuginfo~4.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreadline6", rpm:"libreadline6~6.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreadline6-debuginfo", rpm:"libreadline6-debuginfo~6.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"readline-devel", rpm:"readline-devel~6.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-debuginfo-32bit", rpm:"bash-debuginfo-32bit~4.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreadline6-32bit", rpm:"libreadline6-32bit~6.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreadline6-debuginfo-32bit", rpm:"libreadline6-debuginfo-32bit~6.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"readline-devel-32bit", rpm:"readline-devel-32bit~6.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-doc", rpm:"bash-doc~4.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-lang", rpm:"bash-lang~4.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"eadline-doc", rpm:"eadline-doc~6.2~75.4.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
