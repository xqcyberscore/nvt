###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for pki-core RHSA-2013:0511-02
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
tag_insight = "Red Hat Certificate System is an enterprise software system designed to
  manage enterprise public key infrastructure (PKI) deployments. PKI Core
  contains fundamental packages required by Red Hat Certificate System, which
  comprise the Certificate Authority (CA) subsystem.

  Note: The Certificate Authority component provided by this advisory cannot
  be used as a standalone server. It is installed and operates as a part of
  Identity Management (the IPA component) in Red Hat Enterprise Linux.

  Multiple cross-site scripting flaws were discovered in Certificate System.
  An attacker could use these flaws to perform a cross-site scripting (XSS)
  attack against victims using Certificate System's web interface.
  (CVE-2012-4543)

  This update also fixes the following bugs:

  * Previously, due to incorrect conversion of large integers while
  generating a new serial number, some of the most significant bits in the
  serial number were truncated. Consequently, the serial number generated for
  certificates was sometimes smaller than expected and this incorrect
  conversion in turn led to a collision if a certificate with the smaller
  number already existed in the database. This update removes the incorrect
  integer conversion so that no serial numbers are truncated. As a result,
  the installation wizard proceeds as expected. (BZ#841663)

  * The certificate authority used a different profile for issuing the audit
  certificate than it used for renewing it. The issuing profile was for two
  years, and the renewal was for six months. They should both be for two
  years. This update sets the default and constraint parameters in the
  caSignedLogCert.cfg audit certificate renewal profile to two years.
  (BZ#844459)

  This update also adds the following enhancements:

  * IPA (Identity, Policy and Audit) now provides an improved way to
  determine that PKI is up and ready to service requests. Checking the
  service status was not sufficient. This update creates a mechanism for
  clients to determine that the PKI subsystem is up using the getStatus()
  function to query the cs.startup_state in CS.cfg. (BZ#858864)

  * This update increases the default root CA validity period from eight
  years to twenty years. (BZ#891985)

  All users of pki-core are advised to upgrade to these updated packages,
  which fix these issues and add these enhancements.";


tag_affected = "pki-core on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2013-February/msg00052.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870918");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-02-22 10:01:35 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-4543");
  script_bugtraq_id(56843);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "RHSA", value: "2013:0511-02");
  script_name("RedHat Update for pki-core RHSA-2013:0511-02");

  script_tag(name: "summary" , value: "Check for the Version of pki-core");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"pki-core-debuginfo", rpm:"pki-core-debuginfo~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-native-tools", rpm:"pki-native-tools~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-symkey", rpm:"pki-symkey~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-ca", rpm:"pki-ca~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-common", rpm:"pki-common~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-java-tools", rpm:"pki-java-tools~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-selinux", rpm:"pki-selinux~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-setup", rpm:"pki-setup~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-silent", rpm:"pki-silent~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pki-util", rpm:"pki-util~9.0.3~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
