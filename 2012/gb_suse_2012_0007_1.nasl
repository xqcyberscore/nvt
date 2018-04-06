###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0007_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# SuSE Update for seamonkey openSUSE-SU-2012:0007-1 (seamonkey)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "seamonkey version 2.6 fixes several security issues:

  * MFSA 2011-53/CVE-2011-3660: Miscellaneous memory safety hazards
  * MFSA 2011-54/CVE-2011-3661: Potentially exploitable crash in the
    YARR regular expression library
  * MFSA 2011-55/CVE-2011-3658: nsSVGValue out-of-bounds access
  * MFSA 2011-56/CVE-2011-3663: Key detection without JavaScript via
    SVG animation
  * MFSA 2011-58/CVE-2011-3665: Crash scaling to extreme sizes";

tag_affected = "seamonkey on openSUSE 11.4, openSUSE 11.3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850274");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-08-02 23:16:49 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2011-3658", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "openSUSE-SU", value: "2012:0007_1");
  script_name("SuSE Update for seamonkey openSUSE-SU-2012:0007-1 (seamonkey)");

  script_tag(name: "summary" , value: "Check for the Version of seamonkey");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
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

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.6~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.6~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.6~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.6~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.6~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~2.6~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.6~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.6~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.6~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-common", rpm:"seamonkey-translations-common~2.6~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-translations-other", rpm:"seamonkey-translations-other~2.6~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-venkman", rpm:"seamonkey-venkman~2.6~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
