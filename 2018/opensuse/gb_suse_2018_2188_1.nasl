###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2188_1.nasl 11416 2018-09-17 03:39:26Z ckuersteiner $
#
# SuSE Update for wireshark openSUSE-SU-2018:2188-1 (wireshark)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851832");
  script_version("$Revision: 11416 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 05:39:26 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-04 05:46:51 +0200 (Sat, 04 Aug 2018)");
  script_cve_id("CVE-2018-14339", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14342",
                "CVE-2018-14343", "CVE-2018-14344", "CVE-2018-14368", "CVE-2018-14369",
                "CVE-2018-7325");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for wireshark openSUSE-SU-2018:2188-1 (wireshark)");
  script_tag(name:"summary", value:"Check the version of wireshark");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"
  This update for wireshark fixes the following issues:

  Security issues fixed:

  - CVE-2018-7325: RPKI-Router infinite loop (boo#1082692)
  - CVE-2018-14342: BGP dissector large loop (wnpa-sec-2018-34, boo#1101777)
  - CVE-2018-14344: ISMP dissector crash (wnpa-sec-2018-35, boo#1101788)
  - CVE-2018-14340: Multiple dissectors could crash (wnpa-sec-2018-36,
  boo#1101804)
  - CVE-2018-14343: ASN.1 BER dissector crash (wnpa-sec-2018-37, boo#1101786)
  - CVE-2018-14339: MMSE dissector infinite loop (wnpa-sec-2018-38,
  boo#1101810)
  - CVE-2018-14341: DICOM dissector crash (wnpa-sec-2018-39, boo#1101776)
  - CVE-2018-14368: Bazaar dissector infinite loop (wnpa-sec-2018-40,
  boo#1101794)
  - CVE-2018-14369: HTTP2 dissector crash (wnpa-sec-2018-41, boo#1101800)

  Bug fixes:

  - Further bug fixes and updated protocol support as listed in:
  <a  rel='nofollow' href='https://www.wireshark.org/docs/relnotes/wireshark-2.2.16.html'>https://www.wireshark.org/docs/relnotes/wireshark-2.2.16.html


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended 
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-792=1");
  script_tag(name:"affected", value:"wireshark on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"openSUSE-SU", value:"2018:2188_1");
  script_xref(name:"URL" , value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00005.html");
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

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.2.16~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~2.2.16~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~2.2.16~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~2.2.16~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-ui-gtk", rpm:"wireshark-ui-gtk~2.2.16~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-ui-gtk-debuginfo", rpm:"wireshark-ui-gtk-debuginfo~2.2.16~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~2.2.16~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~2.2.16~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
