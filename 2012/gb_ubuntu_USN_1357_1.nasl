###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1357_1.nasl 7960 2017-12-01 06:58:16Z santu $
#
# Ubuntu Update for openssl USN-1357-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "It was discovered that the elliptic curve cryptography (ECC) subsystem
  in OpenSSL, when using the Elliptic Curve Digital Signature Algorithm
  (ECDSA) for the ECDHE_ECDSA cipher suite, did not properly implement
  curves over binary fields. This could allow an attacker to determine
  private keys via a timing attack. This issue only affected Ubuntu 8.04
  LTS, Ubuntu 10.04 LTS, Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-1945)

  Adam Langley discovered that the ephemeral Elliptic Curve
  Diffie-Hellman (ECDH) functionality in OpenSSL did not ensure thread
  safety while processing handshake messages from clients. This
  could allow a remote attacker to cause a denial of service via
  out-of-order messages that violate the TLS protocol. This issue only
  affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10 and Ubuntu
  11.04. (CVE-2011-3210)

  Nadhem Alfardan and Kenny Paterson discovered that the Datagram
  Transport Layer Security (DTLS) implementation in OpenSSL performed a
  MAC check only if certain padding is valid. This could allow a remote
  attacker to recover plaintext. (CVE-2011-4108)

  Antonio Martin discovered that a flaw existed in the fix to address
  CVE-2011-4108, the DTLS MAC check failure. This could allow a remote
  attacker to cause a denial of service. (CVE-2012-0050)

  Ben Laurie discovered a double free vulnerability in OpenSSL that could
  be triggered when the X509_V_FLAG_POLICY_CHECK flag is enabled. This
  could allow a remote attacker to cause a denial of service. This
  issue only affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10
  and Ubuntu 11.04. (CVE-2011-4109)

  It was discovered that OpenSSL, in certain circumstances involving
  ECDH or ECDHE cipher suites, used an incorrect modular reduction
  algorithm in its implementation of the P-256 and P-384 NIST elliptic
  curves. This could allow a remote attacker to obtain the private
  key of a TLS server via multiple handshake attempts. This issue only
  affected Ubuntu 8.04 LTS. (CVE-2011-4354)

  Adam Langley discovered that the SSL 3.0 implementation in OpenSSL
  did not properly initialize data structures for block cipher
  padding. This could allow a remote attacker to obtain sensitive
  information. (CVE-2011-4576)

  Andrew Chi discovered that OpenSSL, when RFC 3779 support is enabled,
  could trigger an assert when handling an X.509 certificate containing
  certificate-extension data associated with IP address blocks or
  Autonomous System (AS) identifiers. This could allow a remote attacker
  to cause a denial of servi ...

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1357-1";
tag_affected = "openssl on Ubuntu 11.04 ,
  Ubuntu 10.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1357-1/");
  script_id(840887);
  script_version("$Revision: 7960 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 07:58:16 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-02-13 16:29:45 +0530 (Mon, 13 Feb 2012)");
  script_cve_id("CVE-2011-1945", "CVE-2011-3210", "CVE-2011-4108", "CVE-2012-0050",
                "CVE-2011-4109", "CVE-2011-4354", "CVE-2011-4576", "CVE-2011-4577",
                "CVE-2011-4619", "CVE-2012-0027");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1357-1");
  script_name("Ubuntu Update for openssl USN-1357-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
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

if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-1ubuntu4.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-1ubuntu4.6", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8k-7ubuntu8.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8k-7ubuntu8.8", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-5ubuntu1.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-5ubuntu1.2", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-4ubuntu3.15", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-4ubuntu3.15", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
