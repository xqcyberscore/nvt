###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-2819-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842545");
  script_version("$Revision: 7956 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:53:44 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-12-02 06:42:54 +0100 (Wed, 02 Dec 2015)");
  script_cve_id("CVE-2015-4513", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183",
                "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7194",
                "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for thunderbird USN-2819-1");
  script_tag(name: "summary", value: "Check the version of thunderbird");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Christian Holler, David Major, Jesse Ruderman,
Tyson Smith, Boris Zbarsky, Randell Jesup, Olli Pettay, Karl Tomlinson, Jeff Walden,
and Gary Kwong discovered multiple memory safety issues in Thunderbird. If a user
were tricked in to opening a specially crafted message, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2015-4513)

Tyson Smith and David Keeler discovered a use-after-poison and buffer
overflow in NSS. An attacker could potentially exploit these to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2015-7181,
CVE-2015-7182)

Ryan Sleevi discovered an integer overflow in NSPR. An attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2015-7183)

Micha&#322  Bentkowski discovered that adding white-space to hostnames that are
IP addresses can bypass same-origin protections. If a user were tricked in
to opening a specially crafted website in a browser-like context, an
attacker could potentially exploit this to conduct cross-site scripting
(XSS) attacks. (CVE-2015-7188)

Looben Yang discovered a buffer overflow during script interactions with
the canvas element in some circumstances. If a user were tricked in to
opening a specially crafted website in a browser-like context, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Thunderbird. (CVE-2015-7189)

Shinto K Anto discovered that CORS preflight is bypassed when receiving
non-standard Content-Type headers in some circumstances. If a user were
tricked in to opening a specially crafted website in a browser-like
context, an attacker could potentially exploit this to bypass
same-origin restrictions. (CVE-2015-7193)

Gustavo Grieco discovered a buffer overflow in libjar in some
circumstances. If a user were tricked in to opening a specially crafted
website in a browser-like context, an attacker could potentially exploit
this to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2015-7194)

Ehsan Akhgari discovered a mechanism for a web worker to bypass secure
requirements for web sockets. If a user were tricked in to opening a
specially crafted website in  ... 

  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "thunderbird on Ubuntu 15.10 ,
  Ubuntu 15.04 ,
  Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "USN", value: "2819-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2819-1/");
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

if(release == "UBUNTU15.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.4.0+build3-0ubuntu0.15.04.1", rls:"UBUNTU15.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.4.0+build3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.4.0+build3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU15.10")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1:38.4.0+build3-0ubuntu0.15.10.1", rls:"UBUNTU15.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
