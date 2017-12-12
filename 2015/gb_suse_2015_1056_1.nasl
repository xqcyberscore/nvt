###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1056_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for cups openSUSE-SU-2015:1056-1 (cups)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850659");
  script_version("$Revision: 8046 $");
  script_cve_id("CVE-2012-5519", "CVE-2015-1158", "CVE-2015-1159");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-06-13 05:55:09 +0200 (Sat, 13 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for cups openSUSE-SU-2015:1056-1 (cups)");
  script_tag(name: "summary", value: "Check the version of cups");
  script_tag(name: "vuldetect", value: "Get the installed version with the
  help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update fixes the following issues:

  - CVE-2015-1158 and CVE-2015-1159 fixes a possible privilege escalation
  via cross-site scripting and bad print job submission used to replace
  cupsd.conf on server (CUPS STR#4609 CERT-VU-810572 CVE-2015-1158
  CVE-2015-1159 bugzilla.suse.com bsc#924208). In general it is crucial to
  limit access to CUPS to trustworthy users who do not misuse their
  permission to submit print jobs which means to upload arbitrary data
  onto the CUPS server, see
  <a  rel='nofollow' href='https://en.opensuse.org/SDB:CUPS_and_SANE_Firewall_settings'>https://en.opensuse.org/SDB:CUPS_and_SANE_Firewall_settings and cf. the
  entries about CVE-2012-5519 below.");
  script_tag(name: "affected", value: "cups on openSUSE 13.1");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "openSUSE-SU", value: "2015:1056_1");
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

if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-client-debuginfo", rpm:"cups-client-debuginfo~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-ddk", rpm:"cups-ddk~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-ddk-debuginfo", rpm:"cups-ddk-debuginfo~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs-debuginfo", rpm:"cups-libs-debuginfo~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs-32bit", rpm:"cups-libs-32bit~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs-debuginfo-32bit", rpm:"cups-libs-debuginfo-32bit~1.5.4~12.20.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
