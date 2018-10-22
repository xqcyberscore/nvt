###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_8fd21e2a72_python-pycryptodomex_fc28.nasl 11994 2018-10-19 16:13:16Z cfischer $
#
# Fedora Update for python-pycryptodomex FEDORA-2018-8fd21e2a72
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
  script_oid("1.3.6.1.4.1.25623.1.0.875048");
  script_version("$Revision: 11994 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 18:13:16 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-09-08 07:32:13 +0200 (Sat, 08 Sep 2018)");
  script_cve_id("CVE-2018-15560");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for python-pycryptodomex FEDORA-2018-8fd21e2a72");
  script_tag(name:"summary", value:"Check the version of python-pycryptodomex");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"PyCryptodome is a self-contained Python
  package of low-level cryptographic primitives. It&#39 s a fork of PyCrypto.
  It brings several enhancements with respect to the last official version of
  PyCrypto (2.6.1), for instance:

  * Authenticated encryption modes (GCM, CCM, EAX, SIV, OCB)
  * Accelerated AES on Intel platforms via AES-NI
  * Elliptic curves cryptography (NIST P-256 curve only)
  * Better and more compact API (nonce and iv attributes for ciphers,
    automatic generation of random nonces and IVs, simplified CTR
    cipher mode, and more)
  * SHA-3 (including SHAKE XOFs) and BLAKE2 hash algorithms
  * Salsa20 and ChaCha20 stream ciphers
  * scrypt and HKDF
  * Deterministic (EC)DSA
  * Password-protected PKCS#8 key containers
  * Shamirs Secret Sharing scheme
  * Random numbers get sourced directly from the OS (and not from a
    CSPRNG in userspace)
  * Cleaner RSA and DSA key generation (largely based on FIPS 186-4)
  * Major clean ups and simplification of the code base

PyCryptodome is not a wrapper to a separate C library like OpenSSL. To
the largest possible extent, algorithms are implemented in pure
Python. Only the pieces that are extremely critical to performance
(e.g. block ciphers) are implemented as C extensions.

Note: all modules are installed under the Cryptodome package to avoid
conflicts with the PyCrypto library.
");
  script_tag(name:"affected", value:"python-pycryptodomex on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-8fd21e2a72");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6F3KETKIU2JFORRESD4J7D2SWIC2TKHE");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"python-pycryptodomex", rpm:"python-pycryptodomex~3.6.6~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
