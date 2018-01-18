###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_1142_1.nasl 8456 2018-01-18 06:58:40Z teissa $
#
# SuSE Update for MozillaFirefox openSUSE-SU-2013:1142-1 (MozillaFirefox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_id(850497);
  script_version("$Revision: 8456 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 07:58:40 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:39 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-1682", "CVE-2013-1683", "CVE-2013-1684", "CVE-2013-1685",
                "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1688", "CVE-2013-1690",
                "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1695",
                "CVE-2013-1696", "CVE-2013-1697", "CVE-2013-1698", "CVE-2013-1699");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for MozillaFirefox openSUSE-SU-2013:1142-1 (MozillaFirefox)");

  tag_insight = "
  MozillaFirefox was updated to Firefox 22.0 (bnc#825935)

  Following security issues were fixed:
  * MFSA 2013-49/CVE-2013-1682/CVE-2013-1683 Miscellaneous
  memory safety hazards
  * MFSA 2013-50/CVE-2013-1684/CVE-2013-1685/CVE-2013-1686
  Memory corruption found using Address Sanitizer
  * MFSA 2013-51/CVE-2013-1687 (bmo#863933, bmo#866823)
  Privileged content access and execution via XBL
  * MFSA 2013-52/CVE-2013-1688 (bmo#873966) Arbitrary code
  execution within Profiler
  * MFSA 2013-53/CVE-2013-1690 (bmo#857883) Execution of
  unmapped memory through onreadystatechange event
  * MFSA 2013-54/CVE-2013-1692 (bmo#866915) Data in the
  body of XHR HEAD requests leads to CSRF attacks
  * MFSA 2013-55/CVE-2013-1693 (bmo#711043) SVG filters can
  lead to information disclosure
  * MFSA 2013-56/CVE-2013-1694 (bmo#848535) PreserveWrapper
  has inconsistent behavior
  * MFSA 2013-57/CVE-2013-1695 (bmo#849791) Sandbox
  restrictions not applied to nested frame elements
  * MFSA 2013-58/CVE-2013-1696 (bmo#761667) X-Frame-Options
  ignored when using server push with multi-part responses
  * MFSA 2013-59/CVE-2013-1697 (bmo#858101) XrayWrappers
  can be bypassed to run user defined methods in a
  privileged context
  * MFSA 2013-60/CVE-2013-1698 (bmo#876044) getUserMedia
  permission dialog incorrectly displays location
  * MFSA 2013-61/CVE-2013-1699 (bmo#840882) Homograph
  domain spoofing in .com, .net and .name";

  tag_affected = "MozillaFirefox on openSUSE 12.2";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name: "openSUSE-SU", value: "2013:1142_1");
  script_tag(name: "summary" , value: "Check for the Version of MozillaFirefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~22.0~2.51.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~22.0~2.51.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~22.0~2.51.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~22.0~2.51.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~22.0~2.51.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~22.0~2.51.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~22.0~2.51.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~22.0~2.51.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
