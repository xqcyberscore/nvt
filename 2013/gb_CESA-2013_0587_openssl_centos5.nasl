###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssl CESA-2013:0587 centos5
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
tag_insight = "OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
  and Transport Layer Security (TLS v1) protocols, as well as a
  full-strength, general purpose cryptography library.

  It was discovered that OpenSSL leaked timing information when decrypting
  TLS/SSL and DTLS protocol encrypted records when CBC-mode cipher suites
  were used. A remote attacker could possibly use this flaw to retrieve plain
  text from the encrypted packets by using a TLS/SSL or DTLS server as a
  padding oracle. (CVE-2013-0169)

  A NULL pointer dereference flaw was found in the OCSP response verification
  in OpenSSL. A malicious OCSP server could use this flaw to crash
  applications performing OCSP verification by sending a specially-crafted
  response. (CVE-2013-0166)

  It was discovered that the TLS/SSL protocol could leak information about
  plain text when optional compression was used. An attacker able to control
  part of the plain text sent over an encrypted TLS/SSL connection could
  possibly use this flaw to recover other portions of the plain text.
  (CVE-2012-4929)

  Note: This update disables zlib compression, which was previously enabled
  in OpenSSL by default. Applications using OpenSSL now need to explicitly
  enable zlib compression to use it.

  It was found that OpenSSL read certain environment variables even when used
  by a privileged (setuid or setgid) application. A local attacker could use
  this flaw to escalate their privileges. No application shipped with Red Hat
  Enterprise Linux 5 and 6 was affected by this problem. (BZ#839735)

  All OpenSSL users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. For the update to take effect,
  all services linked to the OpenSSL library must be restarted, or the
  system rebooted.";


tag_affected = "openssl on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-March/019264.html");
  script_id(881620);
  script_version("$Revision: 8494 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:57:55 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-03-08 10:19:35 +0530 (Fri, 08 Mar 2013)");
  script_cve_id("CVE-2012-4929", "CVE-2013-0166", "CVE-2013-0169");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "CESA", value: "2013:0587");
  script_name("CentOS Update for openssl CESA-2013:0587 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of openssl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~26.el5_9.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~26.el5_9.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~26.el5_9.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
