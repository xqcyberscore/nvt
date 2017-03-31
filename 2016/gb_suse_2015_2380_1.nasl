###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for xulrunner openSUSE-SU-2015:2380-1 (xulrunner)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851194");
  script_version("$Revision: 2682 $");
  script_tag(name:"last_modification", value:"$Date: 2016-02-17 14:49:05 +0100 (Wed, 17 Feb 2016) $");
  script_tag(name:"creation_date", value:"2016-02-02 17:17:43 +0100 (Tue, 02 Feb 2016)");
  script_cve_id("CVE-2015-7201", "CVE-2015-7205", "CVE-2015-7210", "CVE-2015-7212", 
                "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7222");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for xulrunner openSUSE-SU-2015:2380-1 (xulrunner)");
  script_tag(name: "summary", value: "Check the version of xulrunner");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  Xulrunner was updated to 38.5.0 to fix several security issues.

  The following vulnerabilities were fixed (boo#959277):

  * CVE-2015-7201: Miscellaneous memory safety hazards
  * CVE-2015-7210: Use-after-free in WebRTC when datachannel is used after
  being destroyed
  * CVE-2015-7212: Integer overflow allocating extremely large textures
  * CVE-2015-7205: Underflow through code inspection
  * CVE-2015-7213: Integer overflow in MP4 playback in 64-bit versions
  * CVE-2015-7222: Integer underflow and buffer overflow processing MP4
  metadata in libstagefright
  * CVE-2015-7214: Cross-site reading attack through data and view-source
  URIs");
  script_tag(name: "affected", value: "xulrunner on openSUSE Leap 42.1");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2015:2380_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2015-12/msg00038.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_summary("Check for the Version of xulrunner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:opensuse:opensuse", "login/SSH/success", "ssh/login/release");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~38.5.0~7.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~38.5.0~7.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debugsource", rpm:"xulrunner-debugsource~38.5.0~7.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~38.5.0~7.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-32bit", rpm:"xulrunner-32bit~38.5.0~7.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo-32bit", rpm:"xulrunner-debuginfo-32bit~38.5.0~7.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
