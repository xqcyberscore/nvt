###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-ti-omap4 USN-2542-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842146");
  script_version("$Revision: 7956 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:53:44 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-03-25 06:33:39 +0100 (Wed, 25 Mar 2015)");
  script_cve_id("CVE-2014-7822", "CVE-2014-9419", "CVE-2014-9683", "CVE-2015-1421");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-ti-omap4 USN-2542-1");
  script_tag(name: "summary", value: "Check the version of linux-ti-omap4");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The Linux kernel's splice system call did
not correctly validate its parameters. A local, unprivileged user could exploit
this flaw to cause a denial of service (system crash). (CVE-2014-7822)

A flaw was discovered in how Thread Local Storage (TLS) is handled by the
task switching function in the Linux kernel for x86_64 based machines. A
local user could exploit this flaw to bypass the Address Space Layout
Radomization (ASLR) protection mechanism. (CVE-2014-9419)

Dmitry Chernenkov discovered a buffer overflow in eCryptfs' encrypted file
name decoding. A local unprivileged user could exploit this flaw to cause a
denial of service (system crash) or potentially gain administrative
privileges. (CVE-2014-9683)

Sun Baoliang discovered a use after free flaw in the Linux kernel's SCTP
(Stream Control Transmission Protocol) subsystem during INIT collisions. A
remote attacker could exploit this flaw to cause a denial of service
(system crash) or potentially escalate their privileges on the system.
(CVE-2015-1421)");
  script_tag(name: "affected", value: "linux-ti-omap4 on Ubuntu 12.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "USN", value: "2542-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2542-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-1461-omap4", ver:"3.2.0-1461.81", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
