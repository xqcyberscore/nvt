###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1183_2.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for OpenSSL SUSE-SU-2015:1183-2 (OpenSSL)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851044");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-16 18:53:41 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2015-1789", "CVE-2015-1790", "CVE-2015-4000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for OpenSSL SUSE-SU-2015:1183-2 (OpenSSL)");
  script_tag(name: "summary", value: "Check the version of OpenSSL");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  OpenSSL was updated to fix several security issues.

  * CVE-2015-4000: The Logjam Attack ( weakdh.org ) has been addressed
  by rejecting connections with DH parameters shorter than 1024 bits.
  We now also generate 2048-bit DH parameters by default.
  * CVE-2015-1789: An out-of-bounds read in X509_cmp_time was fixed.
  * CVE-2015-1790: A PKCS7 decoder crash with missing EnvelopedContent
  was fixed.
  * fixed a timing side channel in RSA decryption (bnc#929678)

  Additional changes:

  * In the default SSL cipher string EXPORT ciphers are now disabled.
  This will only get active if applications get rebuilt and actually
  use this string. (bnc#931698)

  Security Issues:

  * CVE-2015-1789
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1789 
  * CVE-2015-1790
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1790 
  * CVE-2015-4000
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000");
  script_tag(name: "affected", value: "OpenSSL on SUSE Linux Enterprise Desktop 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2015:1183_2");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(release == "SLED11.0SP3")
{

  if ((res = isrpmvuln(pkg:"compat-openssl097g", rpm:"compat-openssl097g~0.9.7g~146.22.31.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"compat-openssl097g-32bit", rpm:"compat-openssl097g-32bit~0.9.7g~146.22.31.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}