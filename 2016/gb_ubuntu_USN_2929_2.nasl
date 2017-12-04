###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-lts-trusty USN-2929-2
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
  script_oid("1.3.6.1.4.1.25623.1.0.842690");
  script_version("$Revision: 7955 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:40:43 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-03-15 06:36:33 +0100 (Tue, 15 Mar 2016)");
  script_cve_id("CVE-2016-3134", "CVE-2013-4312", "CVE-2015-7566", "CVE-2015-7833",
		"CVE-2016-0723", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544",
		"CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548",
		"CVE-2016-2549", "CVE-2016-2782");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-lts-trusty USN-2929-2");
  script_tag(name: "summary", value: "Check the version of linux-lts-trusty");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Ben Hawkes discovered that the Linux
  netfilter implementation did not correctly perform validation when handling
  IPT_SO_SET_REPLACE events. A local unprivileged attacker could use this to
  cause a denial of service (system crash) or possibly execute arbitrary code
  with administrative privileges. (CVE-2016-3134)

  It was discovered that the Linux kernel did not properly enforce rlimits
  for file descriptors sent over UNIX domain sockets. A local attacker could
  use this to cause a denial of service. (CVE-2013-4312)

  Ralf Spenneberg discovered that the USB driver for Clie devices in the
  Linux kernel did not properly sanity check the endpoints reported by the
  device. An attacker with physical access could cause a denial of service
  (system crash). (CVE-2015-7566)

  Ralf Spenneberg discovered that the usbvision driver in the Linux kernel
  did not properly sanity check the interfaces and endpoints reported by the
  device. An attacker with physical access could cause a denial of service
  (system crash). (CVE-2015-7833)

  It was discovered that a race condition existed in the ioctl handler for
  the TTY driver in the Linux kernel. A local attacker could use this to
  cause a denial of service (system crash) or expose sensitive information.
  (CVE-2016-0723)

  Andrey Konovalov discovered that the ALSA USB MIDI driver incorrectly
  performed a double-free. A local attacker with physical access could use
  this to cause a denial of service (system crash) or possibly execute
  arbitrary code with administrative privileges. (CVE-2016-2384)

  Dmitry Vyukov discovered that the Advanced Linux Sound Architecture (ALSA)
  framework did not verify that a FIFO was attached to a client before
  attempting to clear it. A local attacker could use this to cause a denial
  of service (system crash). (CVE-2016-2543)

  Dmitry Vyukov discovered that a race condition existed in the Advanced
  Linux Sound Architecture (ALSA) framework between timer setup and closing
  of the client, resulting in a use-after-free. A local attacker could use
  this to cause a denial of service. (CVE-2016-2544)
 
  Dmitry Vyukov discovered a race condition in the timer handling
  implementation of the Advanced Linux Sound Architecture (ALSA) framework,
  resulting in a use-after-free. A local attacker could use this to cause a
  denial of service (system crash). (CVE-2016-2545)

  Dmitry Vyukov discovered race conditions in the Advanced Linux Sound
  Architecture (ALSA) framework's timer ioctls leading to a use-after-free. A
  local attacker could use this to cause a denial of service (system crash)
  or possibly execute arbitrary code. (CVE-2016-2546)

  Dmitry Vyukov discovered th ... 

  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "linux-lts-trusty on Ubuntu 12.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "USN", value: "2929-2");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2929-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-83-generic", ver:"3.13.0-83.127~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-3.13.0-83-generic-lpae", ver:"3.13.0-83.127~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
