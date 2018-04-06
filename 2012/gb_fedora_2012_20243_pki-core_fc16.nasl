###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for pki-core FEDORA-2012-20243
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
tag_insight = "==================================
  **<i>  ABOUT &quot;CERTIFICATE SYSTEM&quot;  **
  </I>==================================

  Certificate System (CS) is an enterprise software system designed
  to manage enterprise Public Key Infrastructure (PKI) deployments.

  PKI Core contains fundamental packages required by Certificate System,
  and consists of the following components:

    * pki-setup
    * pki-symkey
    * pki-native-tools
    * pki-util
    * pki-util-javadoc
    * pki-java-tools
    * pki-java-tools-javadoc
    * pki-common
    * pki-common-javadoc
    * pki-selinux
    * pki-ca
    * pki-silent

  which comprise the following PKI subsystems:

    * Certificate Authority (CA)

  For deployment purposes, Certificate System requires ONE AND ONLY ONE
  of the following &quot;Mutually-Exclusive&quot; PKI Theme packages:

    * ipa-pki-theme    (IPA deployments)
    * dogtag-pki-theme (Dogtag Certificate System deployments)
    * redhat-pki-theme (Red Hat Certificate System deployments)";

tag_affected = "pki-core on Fedora 16";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-December/094995.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864952");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-12-26 12:00:49 +0530 (Wed, 26 Dec 2012)");
  script_cve_id("CVE-2012-4543");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "FEDORA", value: "2012-20243");
  script_name("Fedora Update for pki-core FEDORA-2012-20243");

  script_tag(name: "summary" , value: "Check for the Version of pki-core");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"pki-core", rpm:"pki-core~9.0.25~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
