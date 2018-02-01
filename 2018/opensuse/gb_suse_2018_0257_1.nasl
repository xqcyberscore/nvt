###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0257_1.nasl 8606 2018-01-31 13:07:06Z santu $
#
# SuSE Update for MozillaThunderbird openSUSE-SU-2018:0257-1 (MozillaThunderbird)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851690");
  script_version("$Revision: 8606 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-31 14:07:06 +0100 (Wed, 31 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-28 07:42:28 +0100 (Sun, 28 Jan 2018)");
  script_cve_id("CVE-2018-5089", "CVE-2018-5095", "CVE-2018-5096", "CVE-2018-5097", 
                "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5102", "CVE-2018-5103", 
                "CVE-2018-5104", "CVE-2018-5117");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MozillaThunderbird openSUSE-SU-2018:0257-1 (MozillaThunderbird)");
  script_tag(name: "summary", value: "Check the version of MozillaThunderbird");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update for MozillaThunderbird  to version 52.6 fixes several issues.

  These security issues were fixed:

  - CVE-2018-5095: Integer overflow in Skia library during edge builder
  allocation (bsc#1077291).
  - CVE-2018-5096: Use-after-free while editing form elements (bsc#1077291).
  - CVE-2018-5097: Use-after-free when source document is manipulated during
  XSLT (bsc#1077291).
  - CVE-2018-5098: Use-after-free while manipulating form input elements
  (bsc#1077291).
  - CVE-2018-5099: Use-after-free with widget listener (bsc#1077291).
  - CVE-2018-5102: Use-after-free in HTML media elements (bsc#1077291).
  - CVE-2018-5103: Use-after-free during mouse event handling (bsc#1077291).
  - CVE-2018-5104: Use-after-free during font face manipulation
  (bsc#1077291).
  - CVE-2018-5117: URL spoofing with right-to-left text aligned
  left-to-right (bsc#1077291).
  - CVE-2018-5089: Various memory safety bugs (bsc#1077291).

  These security issues were fixed:

  - Searching message bodies of messages in local folders, including filter
  and quick filter operations, not working reliably: Content not found in
  base64-encode message parts, non-ASCII text not found and false
  positives found.
  - Defective messages (without at least one expected header) not shown in
  IMAP folders but shown on mobile devices
  - Calendar: Unintended task deletion if numlock is enabled");
  script_tag(name: "affected", value: "MozillaThunderbird on openSUSE Leap 42.3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2018:0257_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2018-01/msg00077.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~52.6~56.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~52.6~56.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~52.6~56.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~52.6~56.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~52.6~56.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~52.6~56.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~52.6~56.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~52.6~56.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~52.6~56.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~52.6~56.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~52.6~56.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~52.6~56.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~52.6~56.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~52.6~56.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
