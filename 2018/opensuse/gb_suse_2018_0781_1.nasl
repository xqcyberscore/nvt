###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0781_1.nasl 9478 2018-04-13 13:28:27Z cfischer $
#
# SuSE Update for Linux Kernel openSUSE-SU-2018:0781-1 (Linux Kernel)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851723");
  script_version("$Revision: 9478 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-13 15:28:27 +0200 (Fri, 13 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-03-25 08:21:54 +0200 (Sun, 25 Mar 2018)");
  script_cve_id("CVE-2017-13166", "CVE-2017-15951", "CVE-2017-16644", "CVE-2017-16912", 
                "CVE-2017-16913", "CVE-2017-17975", "CVE-2017-18174", "CVE-2017-18208", 
                "CVE-2018-1000026", "CVE-2018-1068", "CVE-2018-8087");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Linux Kernel openSUSE-SU-2018:0781-1 (Linux Kernel)");
  script_tag(name: "summary", value: "Check the version of the Linux Kernel");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "

  The openSUSE Leap 42.3 kernel was updated to 4.4.120 to receive various
  security and bugfixes.


  The following security bugs were fixed:

  - CVE-2018-8087: Memory leak in the hwsim_new_radio_nl function in
  drivers/net/wireless/mac80211_hwsim.c allowed local users to cause a
  denial of service (memory consumption) by triggering an out-of-array
  error case (bnc#1085053).
  - CVE-2017-13166: An elevation of privilege vulnerability in the v4l2
  video driver was fixed. (bnc#1072865).
  - CVE-2017-18208: The madvise_willneed function in mm/madvise.c in the
  Linux kernel allowed local users to cause a denial of service (infinite
  loop) by triggering use of MADVISE_WILLNEED for a DAX mapping
  (bnc#1083494).
  - CVE-2017-17975: Use-after-free in the usbtv_probe function in
  drivers/media/usb/usbtv/usbtv-core.c allowed attackers to cause a denial
  of service (system crash) or possibly have unspecified other impact by
  triggering failure of audio registration, because a kfree of the usbtv
  data structure occurs during a usbtv_video_free call, but the
  usbtv_video_fail label's code attempts to both access and free this data
  structure (bnc#1074426).
  - CVE-2017-16644: The hdpvr_probe function in
  drivers/media/usb/hdpvr/hdpvr-core.c allowed local users to cause a
  denial of service (improper error handling and system crash) or possibly
  have unspecified other impact via a crafted USB device (bnc#1067118).
  - CVE-2017-15951: The KEYS subsystem in did not correctly synchronize the
  actions of updating versus finding a key in the 'negative' state to
  avoid a race condition, which allowed local users to cause a denial of
  service or possibly have unspecified other impact via crafted system
  calls (bnc#1062840 bnc#1065615).
  - CVE-2018-1000026: An insufficient input validation vulnerability in the
  bnx2x network card driver could result in DoS: Network card firmware
  assertion takes card off-line. This attack appears to be exploitable via
  an attacker that must pass a very large, specially crafted packet to the
  bnx2x card. This could be done from an untrusted guest VM. (bnc#1079384).
  - CVE-2017-18174: In the amd_gpio_remove function in
  drivers/pinctrl/pinctrl-amd.c calls the pinctrl_unregister function,
  which could lead to a double free (bnc#1080533).
  - CVE-2017-16912: The 'get_pipe()' function (drivers/usb/usbip/stub_rx.c)
  allowed attackers to cause a denial of service (out-of-bounds read) via
  a specially crafted USB over IP packet (bnc#1078673).
  - CVE-2017-16913: The 'stub_recv_cmd_submit()' function
  (drivers/usb/usbip/stub_rx.c) when handling CMD_SUBMIT.

  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "Linux Kernel on openSUSE Leap 42.3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2018:0781_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2018-03/msg00054.html");
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

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.4.120~45.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~4.4.120~45.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-docs-pdf", rpm:"kernel-docs-pdf~4.4.120~45.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.4.120~45.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.4.120~45.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kselftests-kmp-debug", rpm:"kselftests-kmp-debug~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kselftests-kmp-debug-debuginfo", rpm:"kselftests-kmp-debug-debuginfo~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kselftests-kmp-default-debuginfo", rpm:"kselftests-kmp-default-debuginfo~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kselftests-kmp-vanilla", rpm:"kselftests-kmp-vanilla~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kselftests-kmp-vanilla-debuginfo", rpm:"kselftests-kmp-vanilla-debuginfo~4.4.120~45.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
