###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1156_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for Xen SUSE-SU-2015:1156-1 (Xen)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851096");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-16 19:56:27 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2015-3209", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-4164");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for Xen SUSE-SU-2015:1156-1 (Xen)");
  script_tag(name: "summary", value: "Check the version of Xen");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  Xen was updated to fix six security issues:

  * CVE-2015-4103: Potential unintended writes to host MSI message data
  field via qemu. (XSA-128, bsc#931625)
  * CVE-2015-4104: PCI MSI mask bits inadvertently exposed to guests.
  (XSA-129, bsc#931626)
  * CVE-2015-4105: Guest triggerable qemu MSI-X pass-through error
  messages. (XSA-130, bsc#931627)
  * CVE-2015-4106: Unmediated PCI register access in qemu. (XSA-131,
  bsc#931628)
  * CVE-2015-3209: heap overflow in qemu pcnet controller allowing guest
  to host escape. (XSA-135, bsc#932770)
  * CVE-2015-4164: DoS through iret hypercall handler. (XSA-136,
  bsc#932996)

  Security Issues:

  * CVE-2015-4103
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4103 
  * CVE-2015-4104
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4104 
  * CVE-2015-4105
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4105 
  * CVE-2015-4106
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4106 
  * CVE-2015-4164
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4164 
  * CVE-2015-3209
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3209 


  Special Instructions and Notes:

  Please reboot the system after installing this update.");
  script_tag(name: "affected", value: "Xen on SUSE Linux Enterprise Server 11 SP1 LTSS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2015:1156_1");
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

if(release == "SLES11.0SP1")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_21548_18_2.6.32.59_0.19~0.25.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.0.3_21548_18_2.6.32.59_0.19~0.25.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.0.3_21548_18~0.25.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_21548_18_2.6.32.59_0.19~0.25.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}