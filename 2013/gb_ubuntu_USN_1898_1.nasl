###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1898_1.nasl 7958 2017-12-01 06:47:47Z santu $
#
# Ubuntu Update for openssl USN-1898-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The TLS protocol 1.2 and earlier can encrypt compressed data without
  properly obfuscating the length of the unencrypted data, which allows
  man-in-the-middle attackers to obtain plaintext content by observing
  length differences during a series of guesses in which a provided string
  potentially matches an unknown string in encrypted and compressed traffic.
  This is known as a CRIME attack in HTTP. Other protocols layered on top of
  TLS may also make these attacks practical.

  This update disables compression for all programs using SSL and TLS
  provided by the OpenSSL library. To re-enable compression for programs
  that need compression to communicate with legacy services, define the
  variable OPENSSL_DEFAULT_ZLIB in the program's environment.";


tag_affected = "openssl on Ubuntu 13.04 ,
  Ubuntu 12.10 ,
  Ubuntu 12.04 LTS ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(841494);
  script_version("$Revision: 7958 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:47:47 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-07-05 13:16:50 +0530 (Fri, 05 Jul 2013)");
  script_cve_id("CVE-2012-4929");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_name("Ubuntu Update for openssl USN-1898-1");

  script_xref(name: "USN", value: "1898-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1898-1/");
  script_summary("Check for the Version of openssl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1-4ubuntu5.10", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8k-7ubuntu8.15", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1c-3ubuntu2.5", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU13.04")
{

  if ((res = isdpkgvuln(pkg:"libssl1.0.0:i386", ver:"1.0.1c-4ubuntu8.1", rls:"UBUNTU13.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
