###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1594_1.nasl 8047 2017-12-08 08:56:07Z santu $
#
# SuSE Update for libxml2 openSUSE-SU-2016:1594-1 (libxml2)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851340");
  script_version("$Revision: 8047 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:56:07 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-06-17 05:19:58 +0200 (Fri, 17 Jun 2016)");
  script_cve_id("CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", 
                "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", 
                "CVE-2016-1840", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4483");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libxml2 openSUSE-SU-2016:1594-1 (libxml2)");
  script_tag(name: "summary", value: "Check the version of libxml2");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update brings libxml2 to version 2.9.4.

  These security issues were fixed:
  - CVE-2016-3627: The xmlStringGetNodeList function in tree.c, when used in
  recovery mode, allowed context-dependent attackers to cause a denial of
  service (infinite recursion, stack consumption, and application crash)
  via a crafted XML document (bsc#972335).
  - CVE-2016-1833: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1834, CVE-2016-1836,
  CVE-2016-1837, CVE-2016-1838, CVE-2016-1839, and CVE-2016-1840
  (bsc#981108).
  - CVE-2016-1835: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document (bsc#981109).
  - CVE-2016-1837: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1834,
  CVE-2016-1836, CVE-2016-1838, CVE-2016-1839, and CVE-2016-1840
  (bsc#981111).
  - CVE-2016-1836: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1834,
  CVE-2016-1837, CVE-2016-1838, CVE-2016-1839, and CVE-2016-1840
  (bsc#981110).
  - CVE-2016-1839: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1834,
  CVE-2016-1836, CVE-2016-1837, CVE-2016-1838, and CVE-2016-1840
  (bsc#981114).
  - CVE-2016-1838: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1834,
  CVE-2016-1836, CVE-2016-1837, CVE-2016-1839, and CVE-2016-1840
  (bsc#981112).
  - CVE-2016-1840: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1834,
  CVE-2016-1836, CVE-2016-1837, CVE-2016-1838, and CVE-2016-1839
  (bsc#981115).
  - CVE-2016-4483: out-of-bounds read parsing an XML using recover mode
  (bnc#978395).
  - CVE-2016-1834: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1836,
 ... 

  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "libxml2 on openSUSE 13.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2016:1594_1");
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

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxml2", rpm:"python-libxml2~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxml2-debuginfo", rpm:"python-libxml2-debuginfo~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxml2-debugsource", rpm:"python-libxml2-debugsource~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-2-debuginfo-32bit", rpm:"libxml2-2-debuginfo-32bit~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel-32bit", rpm:"libxml2-devel-32bit~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
