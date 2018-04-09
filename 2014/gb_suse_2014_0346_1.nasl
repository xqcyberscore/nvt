###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0346_1.nasl 9373 2018-04-06 08:57:18Z cfischer $
#
# SuSE Update for gnutls openSUSE-SU-2014:0346-1 (gnutls)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850573");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-03-12 09:29:15 +0530 (Wed, 12 Mar 2014)");
  script_cve_id("CVE-2013-1619", "CVE-2014-0092");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("SuSE Update for gnutls openSUSE-SU-2014:0346-1 (gnutls)");

  tag_insight = "
  The gnutls library was updated to fix SSL certificate
  validation. Remote man-in-the-middle attackers were able to
  make the verification believe that a SSL certificate is
  valid even though it was not. Also the TLS-CBC timing
  attack vulnerability was fixed.";

  tag_affected = "gnutls on openSUSE 11.4";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "openSUSE-SU", value: "2014:0346_1");
  script_tag(name:"summary", value:"Check for the Version of gnutls");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnutls-debugsource", rpm:"gnutls-debugsource~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls-extra-devel", rpm:"libgnutls-extra-devel~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls-extra26", rpm:"libgnutls-extra26~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls-extra26-debuginfo", rpm:"libgnutls-extra26-debuginfo~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls26", rpm:"libgnutls26~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls26-debuginfo", rpm:"libgnutls26-debuginfo~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls26-32bit", rpm:"libgnutls26-32bit~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls26-debuginfo-32bit", rpm:"libgnutls26-debuginfo-32bit~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls26-debuginfo-x86", rpm:"libgnutls26-debuginfo-x86~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnutls26-x86", rpm:"libgnutls26-x86~2.8.6~5.25.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}