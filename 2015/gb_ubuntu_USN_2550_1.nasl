###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for firefox USN-2550-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.842152");
  script_version("$Revision: 7956 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 06:53:44 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-04-02 07:13:05 +0200 (Thu, 02 Apr 2015)");
  script_cve_id("CVE-2015-0801", "CVE-2015-0802", "CVE-2015-0803", "CVE-2015-0804",
                "CVE-2015-0805", "CVE-2015-0806", "CVE-2015-0807", "CVE-2015-0808",
                "CVE-2015-0811", "CVE-2015-0812", "CVE-2015-0813", "CVE-2015-0814",
                "CVE-2015-0815", "CVE-2015-0816");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for firefox USN-2550-1");
  script_tag(name: "summary", value: "Check the version of firefox");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of
detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Olli Pettay and Boris Zbarsky discovered an
issue during anchor navigations in some circumstances. If a user were tricked in
to opening a specially crafted website, an attacker could potentially exploit this
to bypass same-origin policy restrictions. (CVE-2015-0801)

Bobby Holley discovered that windows created to hold privileged UI content
retained access to privileged internal methods if navigated to
unprivileged content. An attacker could potentially exploit this in
combination with another flaw, in order to execute arbitrary script in a
privileged context. (CVE-2015-0802)

Several type confusion issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-0803, CVE-2015-0804)

Abhishek Arya discovered memory corruption issues during 2D graphics
rendering. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-0805, CVE-2015-0806)

Christoph Kerschbaumer discovered that CORS requests from
navigator.sendBeacon() followed 30x redirections after preflight. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to conduct cross-site request forgery
(XSRF) attacks. (CVE-2015-0807)

Mitchell Harper discovered an issue with memory management of simple-type
arrays in WebRTC. An attacker could potentially exploit this to cause
undefined behaviour. (CVE-2015-0808)

Felix Gr&#246 bert discovered an out-of-bounds read in the QCMS colour
management library. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to obtain
sensitive information. (CVE-2015-0811)

Armin Razmdjou discovered that lightweight themes could be installed
in Firefox without a user approval message, from Mozilla subdomains
over HTTP without SSL. A remote attacker could potentially exploit this by
conducting a Man-In-The-Middle (MITM) attack to install themes without
user approval. (CVE-2015-0812)

Aki Helin discovered a use-after-free when playing MP3 audio files using
the Fluendo MP3 GStreamer plugin in certain circumstances. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via applicatio ... 

  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "firefox on Ubuntu 14.10 ,
  Ubuntu 14.04 LTS ,
  Ubuntu 12.04 LTS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "USN", value: "2550-1");
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-2550-1/");
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

if(release == "UBUNTU14.10")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"37.0+build2-0ubuntu0.14.10.1", rls:"UBUNTU14.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"37.0+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"firefox", ver:"37.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
