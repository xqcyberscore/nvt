###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openssl CESA-2012:0699 centos5 
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
tag_insight = "OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
  and Transport Layer Security (TLS v1) protocols, as well as a
  full-strength, general purpose cryptography library.

  An integer underflow flaw, leading to a buffer over-read, was found in the
  way OpenSSL handled DTLS (Datagram Transport Layer Security) application
  data record lengths when using a block cipher in CBC (cipher-block
  chaining) mode. A malicious DTLS client or server could use this flaw to
  crash its DTLS connection peer. (CVE-2012-2333)
  
  Red Hat would like to thank the OpenSSL project for reporting this issue.
  Upstream acknowledges Codenomicon as the original reporter.
  
  On Red Hat Enterprise Linux 6, this update also fixes an uninitialized
  variable use bug, introduced by the fix for CVE-2012-0884 (released via
  RHSA-2012:0426). This bug could possibly cause an attempt to create an
  encrypted message in the CMS (Cryptographic Message Syntax) format to fail.
  
  All OpenSSL users should upgrade to these updated packages, which contain a
  backported patch to resolve these issues. For the update to take effect,
  all services linked to the OpenSSL library must be restarted, or the system
  rebooted.";

tag_affected = "openssl on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-May/018660.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881096");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:07:52 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-2333", "CVE-2012-0884");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2012:0699");
  script_name("CentOS Update for openssl CESA-2012:0699 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of openssl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8e~22.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8e~22.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~0.9.8e~22.el5_8.4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
