###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_0790_1.nasl 8048 2017-12-08 09:05:48Z santu $
#
# SuSE Update for mbedtls openSUSE-SU-2017:0790-1 (mbedtls)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851527");
  script_version("$Revision: 8048 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:05:48 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-04-07 05:47:40 +0200 (Fri, 07 Apr 2017)");
  script_cve_id("CVE-2017-2784");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for mbedtls openSUSE-SU-2017:0790-1 (mbedtls)");
  script_tag(name: "summary", value: "Check the version of mbedtls");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update to mbedtls 1.3.19 fixes security issues and bugs.

  The following vulnerability was fixed:

  CVE-2017-2784: A remote user could have used a specially crafted
  certificate to cause mbedtls to free a buffer allocated on the stack when
  verifying the validity
  of public key with a secp224k1 curve, which could have
  allowed remote code execution on some platforms (boo#1029017)

  The following non-security changes are included:

  - Add checks to prevent signature forgeries for very large messages while
  using RSA through the PK module in 64-bit systems.
  - Fixed potential livelock during the parsing of a CRL in PEM format");
  script_tag(name: "affected", value: "mbedtls on openSUSE Leap 42.2, openSUSE Leap 42.1");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2017:0790_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"libmbedtls9", rpm:"libmbedtls9~1.3.19~15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmbedtls9-debuginfo", rpm:"libmbedtls9-debuginfo~1.3.19~15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mbedtls-debugsource", rpm:"mbedtls-debugsource~1.3.19~15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mbedtls-devel", rpm:"mbedtls-devel~1.3.19~15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmbedtls9-32bit", rpm:"libmbedtls9-32bit~1.3.19~15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmbedtls9-debuginfo-32bit", rpm:"libmbedtls9-debuginfo-32bit~1.3.19~15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"libmbedtls9", rpm:"libmbedtls9~1.3.19~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmbedtls9-debuginfo", rpm:"libmbedtls9-debuginfo~1.3.19~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mbedtls-debugsource", rpm:"mbedtls-debugsource~1.3.19~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mbedtls-devel", rpm:"mbedtls-devel~1.3.19~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmbedtls9-32bit", rpm:"libmbedtls9-32bit~1.3.19~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmbedtls9-debuginfo-32bit", rpm:"libmbedtls9-debuginfo-32bit~1.3.19~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
