###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for pki-tps FEDORA-2013-9258
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
tag_insight = "Certificate System (CS) is an enterprise software system designed
  to manage enterprise Public Key Infrastructure (PKI) deployments.

  The Token Processing System (TPS) is an optional PKI subsystem that acts
  as a Registration Authority (RA) for authenticating and processing
  enrollment requests, PIN reset requests, and formatting requests from
  the Enterprise Security Client (ESC).

  TPS is designed to communicate with tokens that conform to
  Global Platform's Open Platform Specification.

  TPS communicates over SSL with various PKI backend subsystems (including
  the Certificate Authority (CA), the Data Recovery Manager (DRM), and the
  Token Key Service (TKS)) to fulfill the user's requests.

  TPS also interacts with the token database, an LDAP server that stores
  information about individual tokens.

  For deployment purposes, a TPS requires the following components from the
  PKI Core package:

    * pki-setup
    * pki-native-tools
    * pki-selinux

  and can also make use of the following optional components from the
  PKI CORE package:

    * pki-silent

  Additionally, Certificate System requires ONE AND ONLY ONE of the
  following &quot;Mutually-Exclusive&quot; PKI Theme packages:

    * dogtag-pki-theme (Dogtag Certificate System deployments)
    * redhat-pki-theme (Red Hat Certificate System deployments)


  ==================================
  **<i>  ABOUT CERTIFICATE SYSTEM  **
  </I>==================================
  ${overview}";


tag_solution = "Please Install the Updated Packages.";
tag_affected = "pki-tps on Fedora 17";


if(description)
{
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_id(865691);
  script_version("$Revision: 8542 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-26 07:57:28 +0100 (Fri, 26 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-06-07 10:02:59 +0530 (Fri, 07 Jun 2013)");
  script_cve_id("CVE-2013-1885", "CVE-2013-1886");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Fedora Update for pki-tps FEDORA-2013-9258");

  script_xref(name: "FEDORA", value: "2013-9258");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-June/107862.html");
  script_tag(name: "summary" , value: "Check for the Version of pki-tps");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"pki-tps", rpm:"pki-tps~9.0.11~1.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
