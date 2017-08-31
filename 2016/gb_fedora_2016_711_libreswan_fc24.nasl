###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for libreswan FEDORA-2016-711
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
  script_oid("1.3.6.1.4.1.25623.1.0.807910");
  script_version("$Revision: 6631 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:36:10 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-04-13 05:16:40 +0200 (Wed, 13 Apr 2016)");
  script_cve_id("CVE-2016-3071");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for libreswan FEDORA-2016-711");
  script_tag(name: "summary", value: "Check the version of libreswan");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "Libreswan is a free implementation of
  IPsec &amp  IKE for Linux.  IPsec is the Internet Protocol Security and
  uses strong cryptography to provide both authentication and encryption services.
  These services allow you to build secure tunnels through untrusted networks.
  Everything passing through the untrusted net is encrypted by the ipsec gateway
  machine and decrypted by the gateway at the other end of the tunnel.
  The resulting tunnel is a virtual private network or VPN.

  This package contains the daemons and userland tools for setting up
  Libreswan. To build KLIPS, see the kmod-libreswan.spec file.

  Libreswan also supports IKEv2 (RFC4309) and Secure Labeling

  Libreswan is based on Openswan-2.6.38 which in turn is based on
  FreeS/WAN-2.04");

  script_tag(name: "affected", value: "libreswan on Fedora 24");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-711");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2016-April/182050.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC24")
{

  if ((res = isrpmvuln(pkg:"libreswan", rpm:"libreswan~3.17~1.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
