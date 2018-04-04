###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0851_1.nasl 9288 2018-04-04 06:15:11Z asteins $
#
# SuSE Update for LibVNCServer openSUSE-SU-2018:0851-1 (LibVNCServer)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851728");
  script_version("$Revision: 9288 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-04 08:15:11 +0200 (Wed, 04 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-03-30 08:40:53 +0200 (Fri, 30 Mar 2018)");
  script_cve_id("CVE-2016-9941", "CVE-2016-9942", "CVE-2018-7225");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for LibVNCServer openSUSE-SU-2018:0851-1 (LibVNCServer)");
  script_tag(name: "summary", value: "Check the version of LibVNCServer");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  LibVNCServer was updated to fix two security issues.

  These security issues were fixed:

  - CVE-2018-7225: Missing input sanitization inside rfbserver.c
  rfbProcessClientNormalMessage() (bsc#1081493).
  - CVE-2016-9942: Heap-based buffer overflow in ultra.c allowed remote
  servers to cause a denial of service (application crash) or possibly
  execute arbitrary code via a crafted FramebufferUpdate message with the
  Ultra type tile, such that the LZO payload decompressed length exceeds
  what is specified by the tile dimensions (bsc#1017712).
  - CVE-2016-9941: Heap-based buffer overflow in rfbproto.c allowed remote
  servers to cause a denial of service (application crash) or possibly
  execute arbitrary code via a crafted FramebufferUpdate message
  containing a subrectangle outside of the client drawing area
  (bsc#1017711).

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended 
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-326=1");
  script_tag(name: "affected", value: "LibVNCServer on openSUSE Leap 42.3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2018:0851_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2018-03/msg00073.html");
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

  if ((res = isrpmvuln(pkg:"LibVNCServer-debugsource", rpm:"LibVNCServer-debugsource~0.9.9~16.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"LibVNCServer-devel", rpm:"LibVNCServer-devel~0.9.9~16.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvncclient0", rpm:"libvncclient0~0.9.9~16.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvncclient0-debuginfo", rpm:"libvncclient0-debuginfo~0.9.9~16.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvncserver0", rpm:"libvncserver0~0.9.9~16.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvncserver0-debuginfo", rpm:"libvncserver0-debuginfo~0.9.9~16.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"linuxvnc", rpm:"linuxvnc~0.9.9~16.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"linuxvnc-debuginfo", rpm:"linuxvnc-debuginfo~0.9.9~16.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
